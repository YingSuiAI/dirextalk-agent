package control

import (
	"bytes"
	"crypto/dsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

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
	if err != nil || signed == nil || len(signed.Signers) != 1 {
		return ErrIdentityRejected
	}
	// AWS PKCS7 documents may omit the signer certificate; add only the
	// region-pinned certificates supplied by server configuration.
	signed.Certificates = append(signed.Certificates, certificates...)
	if !bytes.Equal(signed.Content, document) {
		return ErrIdentityRejected
	}
	signer := signed.GetOnlySigner()
	if signer == nil {
		return ErrIdentityRejected
	}
	for _, certificate := range certificates {
		if bytes.Equal(signer.Raw, certificate.Raw) {
			return verifyAWSDSASigner(signed, signer)
		}
	}
	return ErrIdentityRejected
}

var (
	oidPKCS7Data     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDSA           = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
)

type awsIIDIssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type awsIIDAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type awsIIDSignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     awsIIDIssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []awsIIDAttribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []awsIIDAttribute `asn1:"optional,omitempty,tag:1"`
}

type awsIIDDSASignature struct {
	R *big.Int
	S *big.Int
}

// verifyAWSDSASigner performs the DSA verification that crypto/x509 stopped
// supporting in Go 1.16. AWS still signs the EC2 PKCS7 instance identity
// endpoint with the Region-published DSA certificate and SHA-1. The public key
// is not discovered from the proof: it is the exact server-configured,
// Region-pinned certificate selected above.
func verifyAWSDSASigner(signed *pkcs7.PKCS7, certificate *x509.Certificate) error {
	if signed == nil || certificate == nil || len(signed.Signers) != 1 {
		return ErrIdentityRejected
	}
	publicKey, ok := certificate.PublicKey.(*dsa.PublicKey)
	if !ok || publicKey == nil {
		return ErrIdentityRejected
	}
	encodedSigner, err := asn1.Marshal(signed.Signers[0])
	if err != nil {
		return ErrIdentityRejected
	}
	defer clear(encodedSigner)
	var signer awsIIDSignerInfo
	rest, err := asn1.Unmarshal(encodedSigner, &signer)
	if err != nil || len(rest) != 0 || signer.Version != 1 ||
		signer.IssuerAndSerialNumber.SerialNumber == nil ||
		signer.IssuerAndSerialNumber.SerialNumber.Cmp(certificate.SerialNumber) != 0 ||
		!bytes.Equal(signer.IssuerAndSerialNumber.IssuerName.FullBytes, certificate.RawIssuer) ||
		!signer.DigestAlgorithm.Algorithm.Equal(oidSHA1) ||
		!(signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidDSA) ||
			signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidDSAWithSHA1)) ||
		len(signer.AuthenticatedAttributes) != 3 || len(signer.UnauthenticatedAttributes) != 0 {
		return ErrIdentityRejected
	}
	var contentType asn1.ObjectIdentifier
	if readAWSIIDSignedAttribute(signer.AuthenticatedAttributes, oidContentType, &contentType) != nil ||
		!contentType.Equal(oidPKCS7Data) {
		return ErrIdentityRejected
	}
	var expectedDigest []byte
	if readAWSIIDSignedAttribute(signer.AuthenticatedAttributes, oidMessageDigest, &expectedDigest) != nil {
		return ErrIdentityRejected
	}
	contentDigest := sha1.Sum(signed.Content)
	if !bytes.Equal(expectedDigest, contentDigest[:]) {
		return ErrIdentityRejected
	}
	var signingTime time.Time
	if readAWSIIDSignedAttribute(signer.AuthenticatedAttributes, oidSigningTime, &signingTime) != nil ||
		signingTime.Before(certificate.NotBefore) || signingTime.After(certificate.NotAfter) {
		return ErrIdentityRejected
	}
	signedAttributes, err := marshalAWSIIDAttributes(signer.AuthenticatedAttributes)
	if err != nil {
		return ErrIdentityRejected
	}
	defer clear(signedAttributes)
	attributeDigest := sha1.Sum(signedAttributes)
	var signature awsIIDDSASignature
	rest, err = asn1.Unmarshal(signer.EncryptedDigest, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil ||
		!dsa.Verify(publicKey, attributeDigest[:], signature.R, signature.S) {
		return ErrIdentityRejected
	}
	return nil
}

func readAWSIIDSignedAttribute(
	attributes []awsIIDAttribute,
	target asn1.ObjectIdentifier,
	value any,
) error {
	matched := false
	for _, attribute := range attributes {
		if !attribute.Type.Equal(target) {
			continue
		}
		if matched {
			return ErrIdentityRejected
		}
		matched = true
		rest, err := asn1.Unmarshal(attribute.Value.Bytes, value)
		if err != nil || len(rest) != 0 {
			return ErrIdentityRejected
		}
	}
	if !matched {
		return ErrIdentityRejected
	}
	return nil
}

func marshalAWSIIDAttributes(attributes []awsIIDAttribute) ([]byte, error) {
	encoded, err := asn1.Marshal(struct {
		Attributes []awsIIDAttribute `asn1:"set"`
	}{Attributes: attributes})
	if err != nil {
		return nil, ErrIdentityRejected
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &raw)
	if err != nil || len(rest) != 0 || len(raw.Bytes) == 0 {
		clear(encoded)
		return nil, ErrIdentityRejected
	}
	result := bytes.Clone(raw.Bytes)
	clear(encoded)
	return result, nil
}
