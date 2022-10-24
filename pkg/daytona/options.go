package daytona

import (
	"github.com/hashicorp/vault/api"
)

type Option interface {
	Apply(s *SecretUnmarshler)
}

// WithClient allows callers to provice a custom
// vault client
func WithClient(client *api.Client) Option {
	return withClient{client}
}

type withClient struct{ c *api.Client }

func (w withClient) Apply(s *SecretUnmarshler) {
	s.client = w.c
}

// WithTokenString allows callers to provide a token
// in the form of a string
func WithTokenString(token string) Option {
	return withTokenString{token}
}

type withTokenString struct{ token string }

func (w withTokenString) Apply(s *SecretUnmarshler) {
	s.tokenString = w.token
}

// WithTokenFile allows callers to provide a path
// to a file where a vault token is stored
func WithTokenFile(path string) Option {
	return withTokenFile{path}
}

type withTokenFile struct{ path string }

func (w withTokenFile) Apply(s *SecretUnmarshler) {
	s.tokenFile = w.path
}
