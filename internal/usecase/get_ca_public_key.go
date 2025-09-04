package usecase

import (
	"context"
	"crypto"
	"errors"
)

// GetCAPublicKeyOutput is the result of retrieving the CA's public key.
type GetCAPublicKeyOutput struct {
	PublicKey crypto.PublicKey
}

// GetCAPublicKeyService provides the CA public key via the configured CAKeySource.
// No SSH formatting is done here; adapters can marshal/fingerprint as needed.
type GetCAPublicKeyService struct {
	Keys CAKeySource
	Log  Logger
}

func NewGetCAPublicKeyService(keys CAKeySource, log Logger) *GetCAPublicKeyService {
	return &GetCAPublicKeyService{Keys: keys, Log: log}
}

func (s *GetCAPublicKeyService) Execute(ctx context.Context) (GetCAPublicKeyOutput, error) {
	signer, err := s.Keys.Load(ctx)
	if err != nil {
		return GetCAPublicKeyOutput{}, err
	}
	if signer == nil {
		return GetCAPublicKeyOutput{}, errors.New("keystore returned nil signer")
	}
	return GetCAPublicKeyOutput{PublicKey: signer.Public()}, nil
}
