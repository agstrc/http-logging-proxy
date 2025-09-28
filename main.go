package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	logpath := flag.String("logpath", "", "File path to write request/response pairs")
	caCertFile := flag.String("ca-cert", "", "Path to CA certificate file (PEM format)")
	caKeyFile := flag.String("ca-key", "", "Path to CA private key file (PEM format)")
	flag.Parse()

	slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.Info("Starting proxy server")

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	var err error

	if *caCertFile != "" && *caKeyFile != "" {
		caCert, caKey, err = loadCAFromFiles(*caCertFile, *caKeyFile)
		if err != nil {
			slog.Error("Failed to load CA from files", slog.String("error", err.Error()))
			return
		}
		slog.Info("Loaded CA certificate from files")
	} else if *caCertFile != "" || *caKeyFile != "" {
		slog.Error("Both -ca-cert and -ca-key must be provided together")
		return
	} else {
		caCert, caKey, err = GenerateRandomCA()
		if err != nil {
			slog.Error("Failed to generate random CA", slog.String("error", err.Error()))
			return
		}
		slog.Info("Generated random CA certificate")
	}

	certGenerator := NewCertificateGenerator(caCert, caKey)

	var callback func(*http.Request, *http.Response)
	if *logpath != "" {
		callback = createFileCallback(*logpath)
	}

	proxy := NewProxyHandler(&http.Transport{}, certGenerator, callback)

	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{Addr: addr, Handler: http.HandlerFunc(proxy.Proxy)}
	slog.Info("Proxy server listening", slog.String("address", addr))

	if err := server.ListenAndServe(); err != nil {
		slog.Error("Server failed", slog.String("error", err.Error()))
	}
}

// createFileCallback returns a callback function that writes HTTP request/response pairs to a file.
// The callback is thread-safe and appends to the file with timestamps.
func createFileCallback(filepath string) func(*http.Request, *http.Response) {
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		slog.Error("Failed to open log file", slog.String("filepath", filepath), slog.String("error", err.Error()))
		return nil
	}

	var mu sync.Mutex

	return func(req *http.Request, resp *http.Response) {
		mu.Lock()
		defer mu.Unlock()

		timestamp := time.Now().Format("2006-01-02 15:04:05")
		separator := fmt.Sprintf("\n=== %s REQUEST/RESPONSE PAIR ===\n", timestamp)
		file.WriteString(separator)

		file.WriteString("REQUEST:\n")
		if reqDump, err := httputil.DumpRequest(req, true); err == nil {
			file.Write(reqDump)
		} else {
			fmt.Fprintf(file, "Failed to dump request: %v\n", err)
		}

		file.WriteString("\n\nRESPONSE:\n")
		if respDump, err := httputil.DumpResponse(resp, true); err == nil {
			file.Write(respDump)
		} else {
			fmt.Fprintf(file, "Failed to dump response: %v\n", err)
		}

		file.WriteString("\n" + strings.Repeat("=", 50) + "\n\n")
		file.Sync()
	}
}

// loadCAFromFiles loads a CA certificate and private key from PEM files.
func loadCAFromFiles(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if !cert.IsCA {
		return nil, nil, fmt.Errorf("certificate is not a CA certificate")
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM private key")
	}

	var privKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not RSA")
		}
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return cert, privKey, nil
}
