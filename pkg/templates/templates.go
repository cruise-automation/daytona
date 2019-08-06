package templates

import (
	"text/template"

	"github.com/hashicorp/vault/api"
)

// DaytonaTemplate is a wrapper around text/template which provides secrets access
type DaytonaTemplate struct {
	*template.Template

	client SecretFetcher
}

// SecretFetcher is an abstract interface for fetching secrets. (So we can write tests!)
type SecretFetcher interface {
	Read(secretPath string) (*api.Secret, error)
}

// New returns a new daytona template which can render files based on vault secrets
func New(client SecretFetcher) *DaytonaTemplate {
	t := &DaytonaTemplate{
		Template: template.New(""),
		client:   client,
	}

	t.Funcs(map[string]interface{}{
		"secret": t.secret,
	})

	return t
}

func (t *DaytonaTemplate) secret(secretPath string) (*api.Secret, error) {
	return t.client.Read(secretPath)
}
