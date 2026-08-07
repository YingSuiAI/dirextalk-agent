package control

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"github.com/smallstep/pkcs7"
)

// PKCS7IIDVerifier verifies the exact IMDS document bytes against an
// explicitly configured, region-pinned AWS instance-identity certificate.
// Certificate rotation is therefore an intentional server configuration
// change, never a trust-on-first-use path.
type PKCS7IIDVerifier struct {
	certificates map[string][]*x509.Certificate
}

func NewPKCS7IIDVerifier(certificates map[string][][]byte) (*PKCS7IIDVerifier, error) {
	if len(certificates) == 0 {
		return nil, ErrInvalid
	}
	parsed := make(map[string][]*x509.Certificate, len(certificates))
	for region, values := range certificates {
		if !regionPattern.MatchString(region) || len(values) == 0 || len(values) > 4 {
			return nil, ErrInvalid
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			block, rest := pem.Decode(value)
			if block == nil || block.Type != "CERTIFICATE" ||
				len(bytes.TrimSpace(rest)) != 0 {
				return nil, ErrInvalid
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil || len(certificate.Raw) == 0 {
				return nil, ErrInvalid
			}
			key := string(certificate.Raw)
			if _, duplicate := seen[key]; duplicate {
				return nil, ErrInvalid
			}
			seen[key] = struct{}{}
			parsed[region] = append(parsed[region], certificate)
		}
	}
	return &PKCS7IIDVerifier{certificates: parsed}, nil
}

func (verifier *PKCS7IIDVerifier) Verify(document, signature []byte, region string) error {
	if verifier == nil {
		return ErrIdentityRejected
	}
	certificates := verifier.certificates[region]
	if len(document) == 0 || len(document) > maximumProofBytes ||
		len(signature) == 0 || len(signature) > maximumProofBytes || len(certificates) == 0 {
		return ErrIdentityRejected
	}
	compact := strings.Map(func(character rune) rune {
		if character == ' ' || character == '\t' || character == '\r' || character == '\n' {
			return -1
		}
		return character
	}, string(signature))
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil || len(der) == 0 || len(der) > maximumProofBytes {
		clear(der)
		return ErrIdentityRejected
	}
	defer clear(der)
	signed, err := pkcs7.Parse(der)
	if err != nil || signed == nil {
		return ErrIdentityRejected
	}
	// AWS PKCS7 documents may omit the signer certificate; add only the
	// region-pinned certificates supplied by server configuration.
	signed.Certificates = append(signed.Certificates, certificates...)
	if err := signed.Verify(); err != nil || !bytes.Equal(signed.Content, document) {
		return ErrIdentityRejected
	}
	signer := signed.GetOnlySigner()
	if signer == nil {
		return ErrIdentityRejected
	}
	for _, certificate := range certificates {
		if bytes.Equal(signer.Raw, certificate.Raw) {
			return nil
		}
	}
	return ErrIdentityRejected
}
