package awsprovider

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestConsumeBootstrapCredentialsParsesAWSCSVAndWipesInput(t *testing.T) {
	payload := []byte("User name,Access key ID,Secret access key\r\nroot,AKIAABCDEFGHIJKLMNOP,secret-access-key-value-1234567890\r\n")
	wantSecret := []byte("secret-access-key-value-1234567890")

	err := ConsumeBootstrapCredentials(payload, func(credentials *Credentials) error {
		if got := string(credentials.AccessKeyID); got != "AKIAABCDEFGHIJKLMNOP" {
			t.Fatalf("access key ID = %q", got)
		}
		if !bytes.Equal(credentials.SecretAccessKey, wantSecret) || len(credentials.SessionToken) != 0 {
			t.Fatal("credential values were not parsed")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("consume credentials: %v", err)
	}
	if !allZero(payload) {
		t.Fatal("uploaded credential payload was not wiped")
	}
}

func TestConsumeBootstrapCredentialsParsesStrictJSONAndWipesOnConsumerError(t *testing.T) {
	payload := []byte(`{"AccessKeyId":"ASIAABCDEFGHIJKLMNOP","SecretAccessKey":"secret-access-key-value-1234567890","SessionToken":"short-lived-session-token"}`)
	consumerErr := errors.New("consumer failed")
	var captured *Credentials

	err := ConsumeBootstrapCredentials(payload, func(credentials *Credentials) error {
		captured = credentials
		return consumerErr
	})
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("error = %v", err)
	}
	if !allZero(payload) {
		t.Fatal("uploaded credential payload was not wiped")
	}
	if captured == nil || !allZero(captured.AccessKeyID) || !allZero(captured.SecretAccessKey) || !allZero(captured.SessionToken) {
		t.Fatal("parsed credentials were not wiped after consumer returned")
	}
}

func TestConsumeBootstrapCredentialsRejectsAmbiguousOrUnknownShapes(t *testing.T) {
	tests := map[string][]byte{
		"unknown json field":   []byte(`{"AccessKeyId":"AKIAABCDEFGHIJKLMNOP","SecretAccessKey":"secret-access-key-value-1234567890","Region":"us-east-1"}`),
		"duplicate json field": []byte(`{"AccessKeyId":"AKIAABCDEFGHIJKLMNOP","AccessKeyId":"AKIAQRSTUVWXYZABCDEF","SecretAccessKey":"secret-access-key-value-1234567890"}`),
		"duplicate csv header": []byte("Access key ID,Access key ID,Secret access key\nAKIAABCDEFGHIJKLMNOP,AKIAABCDEFGHIJKLMNOP,secret-access-key-value-1234567890\n"),
		"multiple csv rows":    []byte("Access key ID,Secret access key\nAKIAABCDEFGHIJKLMNOP,secret-access-key-value-1234567890\nAKIAQRSTUVWXYZABCDEF,another-secret-access-key-value-1234\n"),
		"invalid access key":   []byte(`{"AccessKeyId":"not-a-key","SecretAccessKey":"secret-access-key-value-1234567890"}`),
		"missing secret":       []byte(`{"AccessKeyId":"AKIAABCDEFGHIJKLMNOP"}`),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			err := ConsumeBootstrapCredentials(payload, func(*Credentials) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("error = %v", err)
			}
			if called {
				t.Fatal("consumer was called for invalid credentials")
			}
			if !allZero(payload) {
				t.Fatal("invalid uploaded payload was not wiped")
			}
		})
	}
}

func TestCredentialErrorsNeverContainUploadedSecret(t *testing.T) {
	secret := "secret-access-key-value-that-must-not-leak"
	payload := []byte(`{"AccessKeyId":"AKIAABCDEFGHIJKLMNOP","SecretAccessKey":"` + secret + `"}`)
	err := ConsumeBootstrapCredentials(payload, func(*Credentials) error {
		return errors.New("provider rejected " + secret)
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error = %v", err)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
