package config

import (
	"errors"
	"fmt"
	"os"
)

const authPathFmtString = "auth/%s/login"

//Config represents an application configurations
type Config struct {
	VaultAddress      string
	TokenPath         string
	K8STokenPath      string
	K8SAuth           bool
	K8SAuthMount      string
	AWSAuth           bool
	AWSAuthMount      string
	GCPAuth           bool
	GCPAuthMount      string
	GCPServiceAccount string
	VaultAuthRoleName string
	RenewalThreshold  int64
	RenewalIncrement  int64
	RenewalInterval   int64
	SecretPayloadPath string
	SecretEnv         bool
	Workers           int
	AutoRenew         bool
	Entrypoint        bool
	InfiniteAuth      bool
	MaximumAuthRetry  int64
	AuthMount         string
}

// BuildDefaultConfigItem uses the following operation: ENV --> arg
func BuildDefaultConfigItem(envKey string, def string) (val string) {
	val = os.Getenv(envKey)
	if val == "" {
		val = def
	}
	return
}

// ValidateAuthType validates that the user has supplied
// a valid authentication type
func (c *Config) ValidateAuthType() bool {
	p := 0
	for _, v := range []bool{c.K8SAuth, c.AWSAuth, c.GCPAuth} {
		if v {
			p++
		}
	}
	if p == 0 || p > 1 {
		return false
	}
	return true
}

// ValidateConfig attempts to perform some generic
// configuration validation
func (c *Config) ValidateConfig() error {
	if c.VaultAuthRoleName == "" {
		return errors.New("You must supply a role name via VAULT_AUTH_ROLE or -vault-auth-role")
	}
	if c.SecretPayloadPath != "" {
		if f, err := os.Stat(c.SecretPayloadPath); err == nil && f.IsDir() {
			return errors.New("The secret path you provided is a directory, please supply a full file path")
		}
	}
	return nil
}

// BuildAuthMountPath attempts to construct a mount path
// if the provided one is empty
func (c *Config) BuildAuthMountPath(path string) {
	if c.AuthMount == "" {
		c.AuthMount = fmt.Sprintf(authPathFmtString, path)
	}
}
