package installer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	CACertPath     = PersistentRoot + "/tls/ca.crt"
	ServerCertPath = PersistentRoot + "/tls/qdrant.crt"
	ServerKeyPath  = PersistentRoot + "/tls/qdrant.key"
)

func ensureLocalTLS(paths Paths, qdrant Identity) error {
	caPath := paths.Resolve(CACertPath)
	certPath := paths.Resolve(ServerCertPath)
	keyPath := paths.Resolve(ServerKeyPath)
	existing := 0
	for _, path := range []string{caPath, certPath, keyPath} {
		if _, err := os.Lstat(path); err == nil {
			existing++
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect TLS material: %w", err)
		}
	}
	if existing != 0 {
		if existing != 3 {
			return fmt.Errorf("partial TLS material exists")
		}
		return validateLocalTLS(caPath, certPath, keyPath, qdrant, paths.Root == "")
	}
	if err := ensureSecureOwnedDirectory(paths, PersistentRoot, 0o750, 0, 0); err != nil {
		return err
	}
	if err := ensureSecureOwnedDirectory(paths, PersistentRoot+"/tls", 0o750, 0, 0); err != nil {
		return err
	}
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate local CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Dirextalk Knowledge Local CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create local CA: %w", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Qdrant key: %w", err)
	}
	serverSerial, err := randomSerial()
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(10, 0, -1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create Qdrant certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("marshal Qdrant key: %w", err)
	}
	if err := writeSecureManagedFile(paths, CACertPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644, 0, 0); err != nil {
		return err
	}
	if err := writeSecureManagedFile(paths, ServerCertPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o644, 0, 0); err != nil {
		return err
	}
	if err := writeSecureManagedFile(paths, ServerKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o640, 0, qdrant.GID); err != nil {
		return err
	}
	return validateLocalTLS(caPath, certPath, keyPath, qdrant, paths.Root == "")
}

func validateLocalTLS(caPath, certPath, keyPath string, qdrant Identity, production bool) error {
	if err := requireTLSFile(caPath, 0o644, 0, -1, production); err != nil {
		return err
	}
	if err := requireTLSFile(certPath, 0o644, 0, -1, production); err != nil {
		return err
	}
	if err := requireTLSFile(keyPath, 0o640, 0, qdrant.GID, production); err != nil {
		return err
	}
	ca, err := readCertificate(caPath)
	if err != nil {
		return err
	}
	server, err := readCertificate(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read Qdrant key: %w", err)
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return fmt.Errorf("invalid Qdrant key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse Qdrant key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || !ecdsaKey.PublicKey.Equal(server.PublicKey) {
		return fmt.Errorf("Qdrant certificate/key mismatch")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{
		Roots: pool, DNSName: "127.0.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify local Qdrant certificate: %w", err)
	}
	return nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return certificate, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		return randomSerial()
	}
	return serial, nil
}

func requireTLSFile(path string, maximumMode os.FileMode, uid, gid int, production bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&^maximumMode != 0 {
		return fmt.Errorf("TLS material is not a protected regular file")
	}
	if !production {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || (gid >= 0 && int(stat.Gid) != gid) {
		return fmt.Errorf("TLS material ownership mismatch")
	}
	return nil
}
