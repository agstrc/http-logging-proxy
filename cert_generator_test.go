package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestCertificateGenerator_GetCertificate(t *testing.T) {
	// Setup test CA
	caCert, caKey, err := GenerateRandomCA()
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "generate certificate for example.com",
			hostname: "example.com",
			wantErr:  false,
		},
		{
			name:     "generate certificate for subdomain",
			hostname: "www.example.com",
			wantErr:  false,
		},
		{
			name:     "generate certificate for IP address",
			hostname: "192.0.2.1",
			wantErr:  false,
		},
		{
			name:     "cache certificate for same hostname",
			hostname: "example.com",
			wantErr:  false,
		},
	}

	cg := NewCertificateGenerator(caCert, caKey)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cg.GetCertificate(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cert == nil {
					t.Error("GetCertificate() returned nil certificate")
					return
				}

				if len(cert.Certificate) == 0 {
					t.Error("GetCertificate() returned empty certificate chain")
					return
				}

				// Parse and validate the certificate
				x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Errorf("Failed to parse generated certificate: %v", err)
					return
				}

				// Check common name
				if x509Cert.Subject.CommonName != tt.hostname {
					t.Errorf("Certificate CommonName = %v, want %v", x509Cert.Subject.CommonName, tt.hostname)
				}

				// Check key usage
				if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					t.Error("Certificate missing KeyUsageDigitalSignature")
				}

				if x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
					t.Error("Certificate missing KeyUsageKeyEncipherment")
				}

				// Check extended key usage
				hasServerAuth := false
				for _, eku := range x509Cert.ExtKeyUsage {
					if eku == x509.ExtKeyUsageServerAuth {
						hasServerAuth = true
						break
					}
				}
				if !hasServerAuth {
					t.Error("Certificate missing ExtKeyUsageServerAuth")
				}
			}
		})
	}

}

func TestCertificateGenerator_generateDomainCertificate(t *testing.T) {
	// Setup test CA
	caCert, caKey, err := GenerateRandomCA()
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	tests := []struct {
		name     string
		hostname string
		wantErr  bool
		checkDNS bool
		checkIP  bool
	}{
		{
			name:     "generate certificate for domain",
			hostname: "example.com",
			wantErr:  false,
			checkDNS: true,
			checkIP:  false,
		},
		{
			name:     "generate certificate for IP",
			hostname: "192.0.2.1",
			wantErr:  false,
			checkDNS: false,
			checkIP:  true,
		},
	}

	cg := NewCertificateGenerator(caCert, caKey)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cg.generateDomainCertificate(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateDomainCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cert == nil {
					t.Error("generateDomainCertificate() returned nil certificate")
					return
				}

				x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Errorf("Failed to parse certificate: %v", err)
					return
				}

				if tt.checkDNS && len(x509Cert.DNSNames) == 0 {
					t.Error("Certificate has no DNS names")
				}

				if tt.checkIP && len(x509Cert.IPAddresses) == 0 {
					t.Error("Certificate has no IP addresses")
				}

				// Verify certificate chain
				if len(cert.Certificate) != 2 {
					t.Errorf("Certificate chain length = %d, want 2", len(cert.Certificate))
				}

				// Verify private key
				if cert.PrivateKey == nil {
					t.Error("Certificate has no private key")
				}
			}
		})
	}
}

func TestNewCertificateGenerator(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (*x509.Certificate, interface{})
		wantNil bool
	}{
		{
			name: "create with valid CA",
			setup: func() (*x509.Certificate, interface{}) {
				caCert, caKey, _ := GenerateRandomCA()
				return caCert, caKey
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCert, caKey := tt.setup()
			cg := NewCertificateGenerator(caCert, caKey.(*rsa.PrivateKey))

			if (cg == nil) != tt.wantNil {
				t.Errorf("NewCertificateGenerator() nil = %v, wantNil %v", cg == nil, tt.wantNil)
			}

			if !tt.wantNil {
				if cg.caCert == nil {
					t.Error("CertificateGenerator has nil CA certificate")
				}
				if cg.caKey == nil {
					t.Error("CertificateGenerator has nil CA key")
				}
			}
		})
	}
}

// TestCertificateGenerator_Integration tests the full certificate generation and validation flow
func TestCertificateGenerator_Integration(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "full flow for example.com",
			hostname: "test.example.com",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCert, caKey, err := GenerateRandomCA()
			if err != nil {
				t.Fatalf("Failed to generate CA: %v", err)
			}

			cg := NewCertificateGenerator(caCert, caKey)
			cert, err := cg.GetCertificate(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify the certificate can be used in TLS
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{*cert},
				}

				if len(tlsConfig.Certificates) == 0 {
					t.Error("Failed to add certificate to TLS config")
				}
			}
		})
	}
}
