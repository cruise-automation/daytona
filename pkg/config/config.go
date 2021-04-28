package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/cruise-automation/daytona/pkg/logging"
)

type AuthMethod string

// Auth methods
const (
	AuthMethodK8s AuthMethod = "K8S"
	AuthMethodAWS AuthMethod = "AWS"
	AuthMethodGCP AuthMethod = "GCP"
)

const authPathFmtString = "auth/%s/login"

// Config represents an application configuration
type Config struct {
	VaultAddress      string
	TokenPath         string
	AuthMethod        AuthMethod
	K8STokenPath      string
	K8SAuthMount      string
	AWSAuthMount      string
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
	PkiIssuer         string
	PkiRole           string
	PkiDomains        string
	PkiPrivateKey     string
	PkiCertificate    string
	PkiUseCaChain     bool
	Log               logging.Config
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
	switch c.AuthMethod {
	case AuthMethodK8s, AuthMethodAWS, AuthMethodGCP:
		return true
	default:
		return false
	}
}

// ValidateConfig attempts to perform some generic
// configuration validation
func (c *Config) ValidateConfig() error {
	if c.VaultAuthRoleName == "" {
		return errors.New("you must supply a role name via VAULT_AUTH_ROLE or -vault-auth-role")
	}
	if c.SecretPayloadPath != "" {
		if f, err := os.Stat(c.SecretPayloadPath); err == nil && f.IsDir() {
			return errors.New("the secret path you provided is a directory, please supply a full file path")
		}
	}
	if (c.PkiIssuer != "" || c.PkiRole != "" || c.PkiDomains != "" || c.PkiPrivateKey != "" || c.PkiCertificate != "") && (c.PkiIssuer == "" || c.PkiRole == "" || c.PkiDomains == "" || c.PkiPrivateKey == "" || c.PkiCertificate == "") {
		return errors.New("one or more required PKI signing values are missing. PKI_ISSUER: " + c.PkiIssuer + ", PKI_ROLE: " + c.PkiRole + ", PKI_DOMAINS: " + c.PkiDomains + ", PKI_PRIVKEY: " + c.PkiPrivateKey + ", PKI_CERT: " + c.PkiCertificate)
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
