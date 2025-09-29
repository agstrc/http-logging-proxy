package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRemoveHopByHopHeaders(t *testing.T) {
	tests := []struct {
		name         string
		inputHeaders map[string]string
		wantRemoved  []string
		wantPresent  []string
	}{
		{
			name: "remove standard hop-by-hop headers",
			inputHeaders: map[string]string{
				"Connection":     "keep-alive",
				"Keep-Alive":     "timeout=5",
				"Content-Type":   "text/html",
				"Content-Length": "123",
			},
			wantRemoved: []string{"Connection", "Keep-Alive"},
			wantPresent: []string{"Content-Type", "Content-Length"},
		},
		{
			name: "remove proxy headers",
			inputHeaders: map[string]string{
				"Proxy-Connection":    "keep-alive",
				"Proxy-Authorization": "Basic abc123",
				"Authorization":       "Bearer token",
			},
			wantRemoved: []string{"Proxy-Connection", "Proxy-Authorization"},
			wantPresent: []string{"Authorization"},
		},
		{
			name: "remove headers listed in Connection",
			inputHeaders: map[string]string{
				"Connection":      "X-Custom-Header",
				"X-Custom-Header": "value",
				"Content-Type":    "text/html",
			},
			wantRemoved: []string{"Connection", "X-Custom-Header"},
			wantPresent: []string{"Content-Type"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for k, v := range tt.inputHeaders {
				headers.Set(k, v)
			}

			removeHopByHopHeaders(headers)

			for _, h := range tt.wantRemoved {
				if headers.Get(h) != "" {
					t.Errorf("Header %s should be removed but is present", h)
				}
			}

			for _, h := range tt.wantPresent {
				if headers.Get(h) == "" {
					t.Errorf("Header %s should be present but is removed", h)
				}
			}
		})
	}
}

func TestProxyHandler_RealHTTPRequest(t *testing.T) {
	if os.Getenv("GOPROXY_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set GOPROXY_INTEGRATION_TEST=1 to run.")
	}

	tests := []struct {
		name       string
		targetURL  string
		method     string
		wantStatus int
	}{
		{
			name:       "GET request to example.com",
			targetURL:  "http://example.com/",
			method:     "GET",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate CA for proxy
			caCert, caKey, err := GenerateRandomCA()
			if err != nil {
				t.Fatalf("Failed to generate CA: %v", err)
			}

			// Create proxy handler with callback
			var mu sync.Mutex
			var capturedReq *http.Request
			var capturedResp *http.Response

			callback := func(req *http.Request, resp *http.Response) {
				mu.Lock()
				defer mu.Unlock()
				capturedReq = req
				capturedResp = resp
			}

			certGenerator := NewCertificateGenerator(caCert, caKey)
			handler := NewProxyHandler(&http.Transport{}, certGenerator, callback)

			// Start proxy server
			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start proxy listener: %v", err)
			}
			defer proxyListener.Close()

			proxyAddr := proxyListener.Addr().String()
			proxyServer := &http.Server{Handler: http.HandlerFunc(handler.Proxy)}
			go proxyServer.Serve(proxyListener)
			defer proxyServer.Close()

			// Wait for server to start
			time.Sleep(100 * time.Millisecond)

			// Create HTTP client configured to use proxy
			proxyURL, err := url.Parse("http://" + proxyAddr)
			if err != nil {
				t.Fatalf("Failed to parse proxy URL: %v", err)
			}

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
				Timeout: 10 * time.Second,
			}

			// Make real request to example.com through proxy
			resp, err := client.Get(tt.targetURL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify response
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			// Read response body to ensure it's valid
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			if len(body) == 0 {
				t.Error("Response body is empty")
			}

			// Verify callback was invoked
			mu.Lock()
			defer mu.Unlock()

			if capturedReq == nil {
				t.Error("Callback was not invoked with request")
			} else {
				if capturedReq.Method != tt.method {
					t.Errorf("Callback request method = %v, want %v", capturedReq.Method, tt.method)
				}
				if capturedReq.URL.Host != "example.com" {
					t.Errorf("Callback request host = %v, want example.com", capturedReq.URL.Host)
				}
			}

			if capturedResp == nil {
				t.Error("Callback was not invoked with response")
			} else {
				if capturedResp.StatusCode != tt.wantStatus {
					t.Errorf("Callback response status = %v, want %v", capturedResp.StatusCode, tt.wantStatus)
				}

				// Verify response body was captured
				if capturedResp.Body != nil {
					capturedBody, err := io.ReadAll(capturedResp.Body)
					if err != nil {
						t.Errorf("Failed to read captured response body: %v", err)
					}
					if len(capturedBody) == 0 {
						t.Error("Captured response body is empty")
					}
				}
			}
		})
	}
}

func TestProxyHandler_RealHTTPSRequest(t *testing.T) {
	if os.Getenv("GOPROXY_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set GOPROXY_INTEGRATION_TEST=1 to run.")
	}

	tests := []struct {
		name       string
		targetURL  string
		method     string
		wantStatus int
	}{
		{
			name:       "GET request to https://example.com",
			targetURL:  "https://example.com/",
			method:     "GET",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate CA for proxy
			caCert, caKey, err := GenerateRandomCA()
			if err != nil {
				t.Fatalf("Failed to generate CA: %v", err)
			}

			// Create proxy handler with callback
			var mu sync.Mutex
			var capturedReq *http.Request
			var capturedResp *http.Response

			callback := func(req *http.Request, resp *http.Response) {
				mu.Lock()
				defer mu.Unlock()
				capturedReq = req
				capturedResp = resp
			}

			certGenerator := NewCertificateGenerator(caCert, caKey)
			handler := NewProxyHandler(&http.Transport{}, certGenerator, callback)

			// Start proxy server
			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start proxy listener: %v", err)
			}
			defer proxyListener.Close()

			proxyAddr := proxyListener.Addr().String()
			proxyServer := &http.Server{Handler: http.HandlerFunc(handler.Proxy)}
			go proxyServer.Serve(proxyListener)
			defer proxyServer.Close()

			// Wait for server to start
			time.Sleep(100 * time.Millisecond)

			// Create HTTP client configured to use proxy
			proxyURL, err := url.Parse("http://" + proxyAddr)
			if err != nil {
				t.Fatalf("Failed to parse proxy URL: %v", err)
			}

			// Create TLS config that trusts the proxy's CA
			certPool := x509.NewCertPool()
			certPool.AddCert(caCert)

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{
						RootCAs: certPool,
					},
				},
				Timeout: 10 * time.Second,
			}

			// Make real HTTPS request to example.com through proxy
			resp, err := client.Get(tt.targetURL)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify response
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Status = %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			// Read response body to ensure it's valid
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			if len(body) == 0 {
				t.Error("Response body is empty")
			}

			// Verify callback was invoked
			mu.Lock()
			defer mu.Unlock()

			if capturedReq == nil {
				t.Error("Callback was not invoked with request")
			} else {
				if capturedReq.Method != tt.method {
					t.Errorf("Callback request method = %v, want %v", capturedReq.Method, tt.method)
				}
				if capturedReq.URL.Host != "example.com" {
					t.Errorf("Callback request host = %v, want example.com", capturedReq.URL.Host)
				}
				if capturedReq.URL.Scheme != "https" {
					t.Errorf("Callback request scheme = %v, want https", capturedReq.URL.Scheme)
				}
			}

			if capturedResp == nil {
				t.Error("Callback was not invoked with response")
			} else {
				if capturedResp.StatusCode != tt.wantStatus {
					t.Errorf("Callback response status = %v, want %v", capturedResp.StatusCode, tt.wantStatus)
				}

				// Verify response body was captured
				if capturedResp.Body != nil {
					capturedBody, err := io.ReadAll(capturedResp.Body)
					if err != nil {
						t.Errorf("Failed to read captured response body: %v", err)
					}
					if len(capturedBody) == 0 {
						t.Error("Captured response body is empty")
					}
				}
			}
		})
	}
}

func TestProxyHandler_RawTCPTunnel(t *testing.T) {
	if os.Getenv("GOPROXY_INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set GOPROXY_INTEGRATION_TEST=1 to run.")
	}

	tests := []struct {
		name       string
		sendData   string
		wantEcho   string
	}{
		{
			name:     "raw TCP tunnel with echo server",
			sendData: "example.com test message",
			wantEcho: "ECHO: example.com test message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start TCP echo server on OS-assigned port
			tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start TCP listener: %v", err)
			}
			defer tcpListener.Close()

			tcpAddr := tcpListener.Addr().String()
			_, tcpPort, err := net.SplitHostPort(tcpAddr)
			if err != nil {
				t.Fatalf("Failed to parse TCP address: %v", err)
			}

			// Channel to signal when echo server is ready
			ready := make(chan struct{})
			// Channel to signal when echo server should stop
			done := make(chan struct{})

			// Start echo server goroutine
			go func() {
				close(ready) // Signal that we're ready to accept

				conn, err := tcpListener.Accept()
				if err != nil {
					select {
					case <-done:
						// Expected close during cleanup
						return
					default:
						t.Logf("TCP accept error: %v", err)
						return
					}
				}
				defer conn.Close()

				// Read data from connection
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					t.Logf("TCP read error: %v", err)
					return
				}

				// Echo back with prefix
				response := []byte("ECHO: " + string(buf[:n]))
				_, err = conn.Write(response)
				if err != nil {
					t.Logf("TCP write error: %v", err)
				}
			}()

			// Wait for echo server to be ready
			<-ready

			// Generate CA for proxy
			caCert, caKey, err := GenerateRandomCA()
			if err != nil {
				t.Fatalf("Failed to generate CA: %v", err)
			}

			certGenerator := NewCertificateGenerator(caCert, caKey)
			handler := NewProxyHandler(&http.Transport{}, certGenerator, nil)

			// Start proxy server on OS-assigned port
			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start proxy listener: %v", err)
			}
			defer proxyListener.Close()

			proxyAddr := proxyListener.Addr().String()
			proxyServer := &http.Server{Handler: http.HandlerFunc(handler.Proxy)}
			go proxyServer.Serve(proxyListener)
			defer proxyServer.Close()

			// Wait for proxy server to start
			time.Sleep(100 * time.Millisecond)

			// Connect to proxy
			proxyConn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				t.Fatalf("Failed to connect to proxy: %v", err)
			}
			defer proxyConn.Close()

			// Send CONNECT request
			connectReq := "CONNECT 127.0.0.1:" + tcpPort + " HTTP/1.1\r\n"
			connectReq += "Host: 127.0.0.1:" + tcpPort + "\r\n"
			connectReq += "\r\n"

			_, err = proxyConn.Write([]byte(connectReq))
			if err != nil {
				t.Fatalf("Failed to send CONNECT request: %v", err)
			}

			// Read CONNECT response
			proxyConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 1024)
			n, err := proxyConn.Read(buf)
			if err != nil {
				t.Fatalf("Failed to read CONNECT response: %v", err)
			}

			response := string(buf[:n])
			if !strings.Contains(response, "200") || !strings.Contains(response, "Connection Established") {
				t.Errorf("Expected 200 Connection Established, got: %s", response)
			}

			// Send test data through tunnel
			_, err = proxyConn.Write([]byte(tt.sendData))
			if err != nil {
				t.Fatalf("Failed to send data through tunnel: %v", err)
			}

			// Read echoed response
			proxyConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			echoBuf := make([]byte, 1024)
			n, err = proxyConn.Read(echoBuf)
			if err != nil {
				t.Fatalf("Failed to read echo response: %v", err)
			}

			gotEcho := string(echoBuf[:n])
			if gotEcho != tt.wantEcho {
				t.Errorf("Echo response = %q, want %q", gotEcho, tt.wantEcho)
			}

			// Signal cleanup
			close(done)
		})
	}
}