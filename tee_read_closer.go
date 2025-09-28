package main

import "io"

// TeeReadCloser wraps an io.ReadCloser and writes all read data to an io.Writer.
// It implements the same semantics as io.TeeReader but with Close support.
type TeeReadCloser struct {
	reader io.ReadCloser
	writer io.Writer
}

// NewTeeReadCloser creates a TeeReadCloser that reads from r and writes to w.
func NewTeeReadCloser(r io.ReadCloser, w io.Writer) *TeeReadCloser {
	return &TeeReadCloser{
		reader: r,
		writer: w,
	}
}

// Read reads data from the underlying reader and writes it to the writer.
// If the write fails, the read operation fails with the write error.
func (t *TeeReadCloser) Read(p []byte) (n int, err error) {
	n, err = t.reader.Read(p)
	if n > 0 {
		if wn, werr := t.writer.Write(p[:n]); werr != nil {
			return wn, werr
		}
	}
	return n, err
}

// Close closes the underlying reader.
func (t *TeeReadCloser) Close() error {
	return t.reader.Close()
}
