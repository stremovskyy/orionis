package client

import "net/http"

type Authenticator interface {
	Authenticate(req *http.Request) error
}

type Config struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Audience     string
	Scopes       []string
}
