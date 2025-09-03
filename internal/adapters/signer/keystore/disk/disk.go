package disk

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/haukened/kamini/internal/usecase"
)

// Store loads CA private key material from disk.
// Supports:
// - PEM with PKCS8/ED25519 private key (unencrypted)
// - OpenSSH private key (unencrypted)
type Store struct {
	Path string
	L    usecase.Logger
}

// New creates a disk-backed key store.
func New(path string, l usecase.Logger) *Store {
	return &Store{Path: path, L: l}
}

var _ usecase.CAKeySource = (*Store)(nil)

func (s *Store) Load(ctx context.Context) (crypto.Signer, error) {
	if err := enforceStrictKeyPerms(s.Path); err != nil {
		return nil, err
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Try PEM first
	if blk, _ := pem.Decode(data); blk != nil {
		// Unencrypted only for MVP
		pk, err := parsePEMPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		if s.L != nil {
			s.L.Info(ctx, "loaded_ca_key", "path", s.Path, "format", "PEM")
		}
		return pk, nil
	}

	// Try OpenSSH private key
	if strings.Contains(string(data), "OPENSSH PRIVATE KEY") {
		k, err := ssh.ParseRawPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse openssh key: %w", err)
		}
		switch sk := k.(type) {
		case ed25519.PrivateKey:
			return sk, nil
		case *ed25519.PrivateKey:
			return *sk, nil
		default:
			return nil, errors.New("unsupported openssh key type: want ed25519")
		}
	}
	return nil, errors.New("unrecognized key format (expect PEM or OpenSSH ed25519)")
}

func parsePEMPrivateKey(der []byte) (crypto.Signer, error) {
	// PKCS8 preferred path
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch sk := k.(type) {
		case ed25519.PrivateKey:
			return sk, nil
		case *ed25519.PrivateKey:
			return *sk, nil
		default:
			return nil, errors.New("unsupported PKCS8 key, want ed25519")
		}
	}
	// Direct ed25519 private key
	if sk, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if k, ok := sk.(ed25519.PrivateKey); ok {
			return k, nil
		}
	}
	// Try legacy formats as needed in the future
	return nil, errors.New("unable to parse ed25519 private key from PEM")
}
