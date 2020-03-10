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
	assert.Equal(t, "you must supply a role name via VAULT_AUTH_ROLE or -vault-auth-role", err.Error())

	config.PkiIssuer = "test"
	config.PkiRole = "test"
	config.PkiDomains = "www.example.com"
	config.PkiCertificate = "test"
	config.VaultAuthRoleName = "test"
	err = config.ValidateConfig()
	assert.Equal(t, "one or more required PKI signing values are missing. PKI_ISSUER: test, PKI_ROLE: test, PKI_DOMAINS: www.example.com, PKI_PRIVKEY: , PKI_CERT: test", err.Error())

	config.PkiIssuer = "test"
	config.PkiRole = "test"
	config.PkiPrivateKey = "test"
	config.PkiCertificate = "test"
	err = config.ValidateConfig()
	if err != nil {
		t.Fatal("got an error in PKI config, didn't expect one, bailing")
	}
}
