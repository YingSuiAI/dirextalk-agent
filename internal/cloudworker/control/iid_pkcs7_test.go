package control

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/smallstep/pkcs7"
)

func TestPKCS7IIDVerifierAcceptsAWSDSASignatureOnCurrentGo(t *testing.T) {
	var signatureDER, certificatePEM []byte
	rest := []byte(awsEC2PKCS7Fixture)
	for len(rest) > 0 {
		block, trailing := pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PKCS7":
			signatureDER = bytes.Clone(block.Bytes)
		case "CERTIFICATE":
			certificatePEM = pem.EncodeToMemory(block)
		}
		rest = trailing
	}
	if len(signatureDER) == 0 || len(certificatePEM) == 0 {
		t.Fatal("AWS EC2 PKCS7 fixture is incomplete")
	}
	signed, err := pkcs7.Parse(signatureDER)
	if err != nil || signed == nil || len(signed.Content) == 0 {
		t.Fatalf("parse AWS EC2 PKCS7 fixture: %v", err)
	}
	verifier, err := NewPKCS7IIDVerifier(map[string][][]byte{
		"us-east-1": {certificatePEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(base64.StdEncoding.EncodeToString(signatureDER))
	document := bytes.Clone(signed.Content)
	if err := verifier.Verify(document, signature, "us-east-1"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	tamperedDocument := bytes.Clone(document)
	tamperedDocument[0] ^= 1
	if err := verifier.Verify(tamperedDocument, signature, "us-east-1"); err == nil {
		t.Fatal("Verify() accepted a tampered instance identity document")
	}
	tamperedSignature := bytes.Clone(signatureDER)
	tamperedSignature[len(tamperedSignature)-1] ^= 1
	if err := verifier.Verify(
		document,
		[]byte(base64.StdEncoding.EncodeToString(tamperedSignature)),
		"us-east-1",
	); err == nil {
		t.Fatal("Verify() accepted a tampered PKCS7 signature")
	}
	if err := verifier.Verify(document, signature, "ap-northeast-1"); err == nil {
		t.Fatal("Verify() accepted a certificate outside its pinned Region")
	}
}

// AWS EC2 instance identity PKCS7 fixture published with the upstream PKCS7
// library. It is signed by the same AWS DSA certificate family used by the
// IMDS PKCS7 endpoint and exercises the Go 1.16+ DSA verification gap.
const awsEC2PKCS7Fixture = `
-----BEGIN PKCS7-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCA
JIAEggGmewogICJwcml2YXRlSXAiIDogIjE3Mi4zMC4wLjI1MiIsCiAgImRldnBh
eVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1
cy1lYXN0LTFhIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3Rh
bmNlSWQiIDogImktZjc5ZmU1NmMiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVs
bCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIg
OiAiMTIxNjU5MDE0MzM0IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwK
ICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDhUMDM6MDE6MzhaIiwKICAiYXJj
aGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJy
YW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAA
AAAxggEYMIIBFAIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5n
dG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2Vi
IFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDgwMzAxNDRaMCMG
CSqGSIb3DQEJBDEWBBTuUc28eBXmImAautC+wOjqcFCBVjAJBgcqhkjOOAQDBC8w
LQIVAKA54NxGHWWCz5InboDmY/GHs33nAhQ6O/ZI86NwjA9Vz3RNMUJrUPU5tAAA
AAAAAA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`
