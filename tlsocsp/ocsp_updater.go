package tlsocsp

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

type CertBundle struct {
	CertPEM   []byte
	KeyPEM    []byte
	IssuerPEM []byte
}

type Updater struct {
	bundle CertBundle
}

func NewUpdater(bundle CertBundle) *Updater {
	return &Updater{bundle: bundle}
}

func (u *Updater) GenerateTLSCertificate() (*tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair(u.bundle.CertPEM, u.bundle.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls pair error: %w", err)
	}

	leafBlock, _ := pem.Decode(u.bundle.CertPEM)
	issuerBlock, _ := pem.Decode(u.bundle.IssuerPEM)
	if leafBlock == nil || issuerBlock == nil {
		return nil, fmt.Errorf("PEM decoding failed")
	}

	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("leaf parse error: %w", err)
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer parse error: %w", err)
	}

	req, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("OCSP create request error: %w", err)
	}

	if len(leaf.OCSPServer) == 0 {
		return nil, fmt.Errorf("no OCSP server found")
	}
	ocspURL := leaf.OCSPServer[0]

	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("OCSP POST error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP HTTP status: %s", resp.Status)
	}

	ocspResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("OCSP read error: %w", err)
	}

	tlsCert.OCSPStaple = ocspResp
	return &tlsCert, nil
}
