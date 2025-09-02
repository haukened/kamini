package domain

import "errors"

var (
	ErrMissingPublicKey = errors.New("missing public key")
	ErrNoPrincipals     = errors.New("no principals")
	ErrInvalidValidity  = errors.New("invalid validity window")
	ErrPolicyDenied     = errors.New("policy denied issuance")
)
