package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
)

const (
	httpsPort = "443"
	httpPort  = "80"
)

var (
	badGatewayMsg     = []byte("Bad gateway")
	invalidRequestMsg = []byte("Invalid request")
	internalErrorMsg  = []byte("Internal server error")
)

// ProxyHandler handles HTTP proxy requests and CONNECT tunneling.
type ProxyHandler struct {
	transport     http.RoundTripper
	certGenerator *CertificateGenerator
	callback      func(*http.Request, *http.Response)
}

// NewProxyHandler creates a new ProxyHandler with the given transport, certificate generator, and optional callback.
func NewProxyHandler(transport http.RoundTripper, certGenerator *CertificateGenerator, callback func(*http.Request, *http.Response)) *ProxyHandler {
	return &ProxyHandler{
		transport:     transport,
		certGenerator: certGenerator,
		callback:      callback,
	}
}

// Proxy handles incoming HTTP requests and CONNECT methods.
func (p *ProxyHandler) Proxy(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		slog.Debug("Handling CONNECT request", slog.String("host", r.RequestURI))
		p.handleConnect(rw, r)
		return
	}

	slog.Debug("Handling HTTP request", slog.String("method", r.Method), slog.String("url", r.RequestURI))
	upstreamRequest, err := p.prepareUpstreamRequest(r)
	if err != nil {
		slog.Warn("Failed to prepare upstream request", slog.String("error", err.Error()), slog.String("method", r.Method), slog.String("url", r.RequestURI))
		p.writeErrorResponse(rw, http.StatusBadRequest, invalidRequestMsg)
		return
	}

	p.forwardRequest(rw, upstreamRequest)
}

// prepareUpstreamRequest creates a new request for forwarding to the upstream server.
func (p *ProxyHandler) prepareUpstreamRequest(r *http.Request) (*http.Request, error) {
	upstreamRequest, err := http.NewRequestWithContext(r.Context(), r.Method, r.RequestURI, r.Body)
	if err != nil {
		return nil, err
	}
	upstreamRequest.Header = r.Header.Clone()
	removeHopByHopHeaders(upstreamRequest.Header)

	return upstreamRequest, nil
}

// prepareTunneledRequest creates a request for forwarding through a CONNECT tunnel.
func (p *ProxyHandler) prepareTunneledRequest(r *http.Request, scheme, host string) *http.Request {
	upstreamRequest := r.Clone(r.Context())
	upstreamRequest.URL.Scheme = scheme
	upstreamRequest.URL.Host = host
	upstreamRequest.RequestURI = ""
	removeHopByHopHeaders(upstreamRequest.Header)
	return upstreamRequest
}

// forwardRequest forwards the request to upstream and streams the response back to the client.
func (p *ProxyHandler) forwardRequest(rw http.ResponseWriter, req *http.Request) {
	slog.Debug("Forwarding request to upstream", slog.String("url", req.URL.String()))

	var (
		requestBody  bytes.Buffer
		responseBody bytes.Buffer
	)

	if req.Body != nil {
		req.Body = NewTeeReadCloser(req.Body, &requestBody)
	}

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		slog.Warn("Failed to forward request to upstream", slog.String("error", err.Error()), slog.String("url", req.URL.String()))
		p.writeErrorResponse(rw, http.StatusBadGateway, badGatewayMsg)
		return
	}
	defer resp.Body.Close()

	slog.Debug("Received response from upstream", slog.Int("status", resp.StatusCode))

	responseHeaders := resp.Header.Clone()
	removeHopByHopHeaders(responseHeaders)
	clear(rw.Header())
	maps.Copy(rw.Header(), responseHeaders)
	rw.WriteHeader(resp.StatusCode)

	teeReader := NewTeeReadCloser(resp.Body, &responseBody)

	_, err = io.Copy(rw, teeReader)
	if err != nil {
		slog.Warn("Failed to copy response body", slog.String("error", err.Error()))
		return
	}

	if p.callback != nil {
		reqCopy := req.Clone(req.Context())
		reqCopy.Body = io.NopCloser(bytes.NewReader(requestBody.Bytes()))

		respCopy := *resp
		respCopy.Body = io.NopCloser(bytes.NewReader(responseBody.Bytes()))

		p.callback(reqCopy, &respCopy)
	}
}

// writeErrorResponse writes an HTTP error response with the given status code and message.
func (p *ProxyHandler) writeErrorResponse(rw http.ResponseWriter, statusCode int, message []byte) {
	rw.WriteHeader(statusCode)
	rw.Write(message)
}

// handleConnect handles HTTP CONNECT requests for tunneling.
func (p *ProxyHandler) handleConnect(rw http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.RequestURI)
	if err != nil {
		slog.Warn("Invalid CONNECT request", slog.String("error", err.Error()), slog.String("requestURI", r.RequestURI))
		p.writeErrorResponse(rw, http.StatusBadRequest, []byte("Invalid CONNECT request: unable to parse host and port"))
		return
	}

	conn, err := p.hijackConnection(rw)
	if err != nil {
		slog.Warn("Failed to hijack connection", slog.String("error", err.Error()))
		p.writeErrorResponse(rw, http.StatusInternalServerError, internalErrorMsg)
		return
	}

	switch port {
	case httpsPort:
		p.handleConnectHTTPS(conn, host, r.Proto)
	case httpPort:
		p.handleConnectHTTP(conn, host, r.Proto)
	default:
		p.handleConnectTCP(conn, host, port, r.Proto)
	}
}

// hijackConnection hijacks the HTTP connection to enable raw TCP communication.
func (p *ProxyHandler) hijackConnection(rw http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("response writer does not support hijacking")
	}

	conn, _, err := hijacker.Hijack()
	return conn, err
}

// getConnectionEstablishedResponse returns a "200 Connection Established" HTTP response.
func getConnectionEstablishedResponse(proto string) []byte {
	return fmt.Appendf(nil, "%s 200 Connection Established\r\n\r\n", proto)
}

// handleConnectTCP establishes a transparent TCP tunnel to the target server.
func (p *ProxyHandler) handleConnectTCP(conn net.Conn, host, port, proto string) {
	slog.Debug("Setting up TCP passthrough", slog.String("host", host), slog.String("port", port))

	response := getConnectionEstablishedResponse(proto)
	if _, err := conn.Write(response); err != nil {
		slog.Error("Failed to write connection established response", slog.String("error", err.Error()))
		conn.Close()
		return
	}

	target := net.JoinHostPort(host, port)
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		slog.Warn("Failed to connect to upstream TCP server", slog.String("target", target), slog.String("error", err.Error()))
		conn.Close()
		return
	}
	defer upstream.Close()

	slog.Debug("TCP connection established", slog.String("target", target))

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(upstream, conn)
		if err != nil {
			slog.Debug("Client to upstream copy finished", slog.String("error", err.Error()))
		}
		upstream.Close()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(conn, upstream)
		if err != nil {
			slog.Debug("Upstream to client copy finished", slog.String("error", err.Error()))
		}
		conn.Close()
	}()

	<-done
	slog.Debug("TCP tunnel closed", slog.String("target", target))
}

// handleConnectHTTPS establishes an HTTPS connection with TLS termination and certificate generation.
func (p *ProxyHandler) handleConnectHTTPS(conn net.Conn, host, proto string) {
	slog.Debug("Setting up HTTPS connection", slog.String("host", host))
	response := getConnectionEstablishedResponse(proto)
	if _, err := conn.Write(response); err != nil {
		slog.Error("Failed to write connection established response", slog.String("error", err.Error()))
		return
	}

	certificate, err := p.certGenerator.GetCertificate(host)
	if err != nil {
		slog.Error("Failed to generate certificate", slog.String("host", host), slog.String("error", err.Error()))
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Warn("TLS handshake failed", slog.String("error", err.Error()))
		return
	}
	slog.Debug("TLS handshake successful", slog.String("host", host))

	p.serveConnWithHandler(tlsConn, host, true)
}

// handleConnectHTTP establishes an HTTP connection for proxying.
func (p *ProxyHandler) handleConnectHTTP(conn net.Conn, host, proto string) {
	slog.Debug("Setting up HTTP connection", slog.String("host", host))
	response := getConnectionEstablishedResponse(proto)
	if _, err := conn.Write(response); err != nil {
		slog.Error("Failed to write connection established response", slog.String("error", err.Error()))
		return
	}
	p.serveConnWithHandler(conn, host, false)
}

// serveConnWithHandler serves HTTP requests over the hijacked connection.
func (p *ProxyHandler) serveConnWithHandler(conn net.Conn, host string, isTLS bool) {
	scheme := "https"
	if !isTLS {
		scheme = "http"
	}

	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		upstreamReq := p.prepareTunneledRequest(r, scheme, host)
		p.forwardRequest(rw, upstreamReq)
	})

	server := &http.Server{Handler: handler}

	server.ConnState = func(c net.Conn, cs http.ConnState) {
		if cs == http.StateClosed || cs == http.StateHijacked {
			server.Close()
		}
	}

	listener := NewSingleListener(conn)
	server.Serve(listener)
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders removes hop-by-hop headers that should not be forwarded.
func removeHopByHopHeaders(header http.Header) {
	for _, connHeader := range header.Values("Connection") {
		header.Del(connHeader)
	}

	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}
