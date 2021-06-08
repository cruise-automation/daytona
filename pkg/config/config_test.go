package config

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func (c *Config) GenerateStandardTestConfig() {
	c.AuthMethod = "K8S"
	c.MaximumAuthRetry = 1
}

func TestInvalidConfig(t *testing.T) {
	var config Config
	config.AuthMethod = "UNKNOWN"
	err := config.ValidateConfig()
	if err == nil {
		t.Fatal("expected an error from invalid config")
	}

	config.AuthMethod = "K8S"
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

func TestValidateAuthType(t *testing.T) {
	var config Config

	// If not set try to pull from env
	os.Setenv("AUTH_METHOD", "k8s")
	ok := config.ValidateAuthType()
	assert.True(t, ok, "expected auth type to be valid")
	assert.Equal(t, "auth/kubernetes/login", config.AuthPath)

	os.Setenv("AUTH_METHOD", "unknown")
	config.AuthMethod = ""
	config.AuthMount = ""
	config.AuthPath = ""
	ok = config.ValidateAuthType()
	assert.False(t, ok, "expected auth type to be invalid")

	config.AuthMethod = "UNKNOWN"
	config.AuthMount = ""
	config.AuthPath = ""
	ok = config.ValidateAuthType()
	assert.False(t, ok, "expected auth type to be invalid")

	config.AuthMethod = "K8S"
	config.AuthMount = ""
	config.AuthPath = ""
	ok = config.ValidateAuthType()
	assert.True(t, ok, "expected auth type to be valid")
	assert.Equal(t, "auth/kubernetes/login", config.AuthPath)

	config.AuthMethod = "AWS"
	config.AuthMount = ""
	config.AuthPath = ""
	ok = config.ValidateAuthType()
	assert.True(t, ok, "expected auth type to be valid")
	assert.Equal(t, "auth/aws/login", config.AuthPath)

	config.AuthMethod = "GCP"
	config.AuthMount = ""
	config.AuthPath = ""
	ok = config.ValidateAuthType()
	assert.True(t, ok, "expected auth type to be valid")
	assert.Equal(t, "auth/gcp/login", config.AuthPath)

	config.AuthMethod = "K8S"
	config.AuthMount = "is-set"
	config.AuthPath = ""
	ok = config.ValidateAuthType()
	assert.True(t, ok, "expected auth type to be valid")
	assert.Equal(t, "auth/is-set/login", config.AuthPath)

	config.AuthMethod = "K8S"
	config.AuthMount = ""
	config.AuthPath = "is-set"
	ok = config.ValidateAuthType()
	assert.True(t, ok, "expected auth type to be valid")
	assert.Equal(t, "is-set", config.AuthPath)
}

func TestAuthMethodParse(t *testing.T) {
	authMethod := new(AuthMethod)
	f := flag.NewFlagSet("test", flag.ContinueOnError)

	f.Var(authMethod, "auth-method", "test")
	args := []string{
		"-auth-method",
		"testAuth",
	}

	err := f.Parse(args)
	assert.NoError(t, err)
	assert.True(t, f.Parsed(), "f.Parse() = false after Parse")
	assert.Equal(t, "TESTAUTH", authMethod.String())
}
