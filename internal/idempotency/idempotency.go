package idempotency

import "errors"

var ErrConflict = errors.New("idempotency key was used with different input")
