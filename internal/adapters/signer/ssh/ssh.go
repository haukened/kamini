package ssh

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	sshx "golang.org/x/crypto/ssh"

	"github.com/haukened/kamini/internal/domain"
	"github.com/haukened/kamini/internal/usecase"
)

// OpenSSHSigner is a pure-Go signer that issues OpenSSH user certificates.
// It relies on a CAKeySource to retrieve the private key material.
type OpenSSHSigner struct {
	keys usecase.CAKeySource
	log  usecase.Logger
}

var _ usecase.Signer = (*OpenSSHSigner)(nil)

func NewOpenSSHSigner(keys usecase.CAKeySource, log usecase.Logger) *OpenSSHSigner {
	return &OpenSSHSigner{keys: keys, log: log}
}

// Sign issues an OpenSSH user certificate for the provided spec and serial.
// Returns the raw marshaled certificate bytes and the CA public key fingerprint (SHA256).
func (s *OpenSSHSigner) Sign(spec domain.CertSpec, serial uint64) ([]byte, string, error) {
	if spec.PublicKeyAuthorized == "" {
		return nil, "", domain.ErrMissingPublicKey
	}
	pub, _, _, _, err := sshx.ParseAuthorizedKey([]byte(spec.PublicKeyAuthorized))
	if err != nil {
		return nil, "", err
	}

	// Load CA private key material.
	priv, err := s.keys.Load(context.Background())
	if err != nil {
		return nil, "", err
	}
	if priv == nil {
		return nil, "", errors.New("keystore returned nil signer")
	}
	caSigner, err := sshx.NewSignerFromSigner(priv)
	if err != nil {
		return nil, "", err
	}

	// Build certificate.
	cert := &sshx.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        sshx.UserCert,
		KeyId:           spec.KeyID,
		ValidPrincipals: append([]string(nil), spec.Principals...),
		ValidAfter:      uint64(spec.ValidAfter.Unix()),
		ValidBefore:     uint64(spec.ValidBefore.Unix()),
		Permissions: sshx.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}

	// Copy options and extensions.
	for k, v := range spec.CriticalOptions {
		cert.Permissions.CriticalOptions[k] = v
	}
	for k, v := range spec.Extensions {
		cert.Permissions.Extensions[k] = v
	}

	// Sign the certificate with the CA signer.
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, "", err
	}

	// Marshal to raw OpenSSH certificate bytes.
	raw := cert.Marshal()
	fp := sshx.FingerprintSHA256(caSigner.PublicKey())

	// Optional debug log (non-PII): serial, principals, validity.
	if s.log != nil {
		s.log.Debug(context.Background(), "signed user cert",
			"serial", serial,
			"principals", spec.Principals,
			"valid_after", spec.ValidAfter.Format(time.RFC3339),
			"valid_before", spec.ValidBefore.Format(time.RFC3339),
		)
	}

	return raw, fp, nil
}
