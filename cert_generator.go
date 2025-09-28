package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertificateGenerator generates and caches TLS certificates for hostnames.
type CertificateGenerator struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	certCache sync.Map
}

// NewCertificateGenerator creates a new CertificateGenerator with the given CA certificate and key.
func NewCertificateGenerator(caCert *x509.Certificate, caKey *rsa.PrivateKey) *CertificateGenerator {
	return &CertificateGenerator{
		caCert: caCert,
		caKey:  caKey,
	}
}

// GetCertificate returns a TLS certificate for the given hostname.
// Certificates are cached and reused for the same hostname.
func (cg *CertificateGenerator) GetCertificate(hostname string) (*tls.Certificate, error) {
	if cert, ok := cg.certCache.Load(hostname); ok {
		return cert.(*tls.Certificate), nil
	}

	cert, err := cg.generateDomainCertificate(hostname)
	if err != nil {
		return nil, err
	}
	cg.certCache.Store(hostname, cert)
	return cert, nil
}

// generateDomainCertificate creates a new TLS certificate for the given hostname.
func (cg *CertificateGenerator) generateDomainCertificate(hostname string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cg.caCert, &priv.PublicKey, cg.caKey)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes, cg.caCert.Raw},
		PrivateKey:  priv,
	}
	return &cert, nil
}
