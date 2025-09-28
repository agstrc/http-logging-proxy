package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// SingleListener implements net.Listener for a single connection.
// It returns the connection once and then blocks until closed.
type SingleListener struct {
	conn      net.Conn
	accepted  atomic.Bool
	closeChan chan struct{}
	closeOnce sync.Once
}

// NewSingleListener creates a new SingleListener that wraps the given connection.
func NewSingleListener(conn net.Conn) *SingleListener {
	return &SingleListener{
		conn:      conn,
		closeChan: make(chan struct{}),
	}
}

// Accept returns the wrapped connection once, then blocks until Close is called.
func (l *SingleListener) Accept() (net.Conn, error) {
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}

	<-l.closeChan
	return nil, errors.New("listener closed")
}

// Close closes the listener and unblocks any blocked Accept calls.
func (l *SingleListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeChan)
	})
	return nil
}

// Addr returns the local address of the wrapped connection.
func (l *SingleListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}
