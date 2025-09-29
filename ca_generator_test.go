package main

import (
	"crypto/x509"
	"testing"
)

func TestGenerateRandomCA(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "generate valid CA certificate",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, err := GenerateRandomCA()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cert == nil {
					t.Error("GenerateRandomCA() returned nil certificate")
				}
				if key == nil {
					t.Error("GenerateRandomCA() returned nil private key")
				}

				if cert.Subject.CommonName != "Random CA" {
					t.Errorf("GenerateRandomCA() CommonName = %v, want Random CA", cert.Subject.CommonName)
				}

				if !cert.IsCA {
					t.Error("GenerateRandomCA() certificate is not a CA")
				}

				if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
					t.Error("GenerateRandomCA() certificate missing KeyUsageCertSign")
				}

				if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
					t.Error("GenerateRandomCA() certificate missing KeyUsageCRLSign")
				}

				if !cert.BasicConstraintsValid {
					t.Error("GenerateRandomCA() certificate has invalid basic constraints")
				}

				if cert.NotBefore.IsZero() {
					t.Error("GenerateRandomCA() certificate has zero NotBefore")
				}

				if cert.NotAfter.IsZero() {
					t.Error("GenerateRandomCA() certificate has zero NotAfter")
				}
			}
		})
	}
}