package server

import (
	"context"
	"errors"
)

var (
	ErrClientNotFound = errors.New("orionis server: client not found")
	ErrUnauthorized   = errors.New("orionis server: unauthorized client")
)

type Client struct {
	ID               string   `json:"id"`
	AllowedAudiences []string `json:"allowed_audiences"`
	AllowedScopes    []string `json:"allowed_scopes"`
}

type ClientStore interface {
	FindClient(ctx context.Context, id string) (Client, error)
}
