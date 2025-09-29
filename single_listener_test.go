package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

type mockConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestNewSingleListener(t *testing.T) {
	tests := []struct {
		name string
		conn net.Conn
	}{
		{
			name: "create listener with valid connection",
			conn: &mockConn{
				localAddr:  &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
				remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 12345},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := NewSingleListener(tt.conn)

			if listener == nil {
				t.Error("NewSingleListener() returned nil")
				return
			}

			if listener.conn != tt.conn {
				t.Error("NewSingleListener() did not store connection")
			}

			if listener.closeChan == nil {
				t.Error("NewSingleListener() did not create close channel")
			}
		})
	}
}

func TestSingleListener_Accept(t *testing.T) {
	tests := []struct {
		name         string
		acceptCount  int
		wantConn     bool
		wantErr      bool
		errOnAccept  int
	}{
		{
			name:        "first accept returns connection",
			acceptCount: 1,
			wantConn:    true,
			wantErr:     false,
		},
		{
			name:        "second accept blocks until close",
			acceptCount: 2,
			wantConn:    false,
			wantErr:     true,
			errOnAccept: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockConn{
				localAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
			}
			listener := NewSingleListener(mockConn)

			for i := 1; i <= tt.acceptCount; i++ {
				if i == tt.errOnAccept {
					// Close listener in background and then accept
					go func() {
						time.Sleep(10 * time.Millisecond)
						listener.Close()
					}()
				}

				conn, err := listener.Accept()

				if i == 1 {
					// First accept should always succeed
					if err != nil {
						t.Errorf("First Accept() unexpected error: %v", err)
					}
					if conn != mockConn {
						t.Error("Accept() did not return expected connection")
					}
				} else if i == tt.errOnAccept {
					// Should get error after close
					if err == nil {
						t.Error("Accept() expected error after close, got nil")
					}
					if conn != nil {
						t.Error("Accept() returned connection after close")
					}
				}
			}
		})
	}
}

func TestSingleListener_Accept_Concurrent(t *testing.T) {
	tests := []struct {
		name        string
		goroutines  int
		wantSuccess int
	}{
		{
			name:        "multiple concurrent accepts",
			goroutines:  5,
			wantSuccess: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockConn{
				localAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
			}
			listener := NewSingleListener(mockConn)

			var wg sync.WaitGroup
			successCount := 0
			var mu sync.Mutex

			// Start multiple goroutines trying to accept
			for i := 0; i < tt.goroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := listener.Accept()
					if err == nil && conn != nil {
						mu.Lock()
						successCount++
						mu.Unlock()
					}
				}()
			}

			// Give goroutines time to start and race for the connection
			time.Sleep(50 * time.Millisecond)

			// Close the listener to unblock any waiting accepts
			listener.Close()

			wg.Wait()

			if successCount != tt.wantSuccess {
				t.Errorf("Successful accepts = %d, want %d", successCount, tt.wantSuccess)
			}
		})
	}
}

func TestSingleListener_Close(t *testing.T) {
	tests := []struct {
		name       string
		closeTimes int
		wantErr    bool
	}{
		{
			name:       "close once",
			closeTimes: 1,
			wantErr:    false,
		},
		{
			name:       "close multiple times",
			closeTimes: 3,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockConn{
				localAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
			}
			listener := NewSingleListener(mockConn)

			for i := 0; i < tt.closeTimes; i++ {
				err := listener.Close()
				if (err != nil) != tt.wantErr {
					t.Errorf("Close() call %d error = %v, wantErr %v", i+1, err, tt.wantErr)
				}
			}
		})
	}
}

func TestSingleListener_Addr(t *testing.T) {
	tests := []struct {
		name     string
		conn     net.Conn
		wantAddr string
	}{
		{
			name: "get address from connection",
			conn: &mockConn{
				localAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
			},
			wantAddr: "192.0.2.1:443",
		},
		{
			name:     "nil connection returns nil address",
			conn:     nil,
			wantAddr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := NewSingleListener(tt.conn)
			addr := listener.Addr()

			if tt.wantAddr == "" {
				if addr != nil {
					t.Errorf("Addr() = %v, want nil", addr)
				}
			} else {
				if addr == nil {
					t.Error("Addr() returned nil, want address")
					return
				}
				if addr.String() != tt.wantAddr {
					t.Errorf("Addr() = %v, want %v", addr.String(), tt.wantAddr)
				}
			}
		})
	}
}

func TestSingleListener_Integration(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "full lifecycle for example.com connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockConn{
				localAddr:  &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
				remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 54321},
			}

			listener := NewSingleListener(mockConn)

			// Verify address
			if listener.Addr() == nil {
				t.Error("Listener has no address")
			}

			// Accept connection
			conn, err := listener.Accept()
			if err != nil {
				t.Errorf("Accept() error = %v", err)
			}
			if conn != mockConn {
				t.Error("Accept() returned wrong connection")
			}

			// Close listener
			if err := listener.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}

			// Accept after close should fail
			conn, err = listener.Accept()
			if err == nil {
				t.Error("Accept() after close should fail")
			}
			if conn != nil {
				t.Error("Accept() after close returned non-nil connection")
			}
		})
	}
}