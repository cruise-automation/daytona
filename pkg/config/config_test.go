package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func (c *Config) GenerateStandardTestConfig() {
	c.K8SAuth = true
	c.MaximumAuthRetry = 1
}

func TestInvalidConfig(t *testing.T) {
	var config Config
	config.K8SAuth = true
	config.AWSAuth = true
	config.GCPAuth = false
	err := config.ValidateConfig()
	if err == nil {
		t.Fatal("expected an error from invalid config")
	}

	config.K8SAuth = true
	config.AWSAuth = false
	config.GCPAuth = false
	err = config.ValidateConfig()
	assert.Equal(t, "You must supply a role name via VAULT_AUTH_ROLE or -vault-auth-role", err.Error())
}
