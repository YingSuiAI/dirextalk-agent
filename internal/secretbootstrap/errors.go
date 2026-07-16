package secretbootstrap

import "errors"

var (
	ErrNotFound           = errors.New("secret bootstrap session not found")
	ErrAlreadyExists      = errors.New("secret bootstrap session already exists")
	ErrRevisionConflict   = errors.New("secret bootstrap revision conflict")
	ErrStateConflict      = errors.New("secret bootstrap state conflict")
	ErrExpired            = errors.New("secret bootstrap session expired")
	ErrInvalidContext     = errors.New("invalid secret bootstrap context")
	ErrInvalidUploadToken = errors.New("invalid secret bootstrap upload token")
	ErrInvalidEnvelope    = errors.New("invalid secret bootstrap envelope")
	ErrKeyUnavailable     = errors.New("secret bootstrap key unavailable")
	ErrConsumerFailed     = errors.New("secret bootstrap consumer failed")
)
