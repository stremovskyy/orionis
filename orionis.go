package orionis

import "errors"

const (
	TokenTypeBearer = "Bearer"
	TokenUseAccess  = "access"
)

var (
	ErrMissingToken      = errors.New("orionis: missing bearer token")
	ErrInvalidToken      = errors.New("orionis: invalid token")
	ErrInsufficientScope = errors.New("orionis: insufficient scope")
)
