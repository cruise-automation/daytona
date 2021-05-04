package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cruise-automation/daytona/pkg/logging"
)

type AuthMethod string

func (a *AuthMethod) String() string {
	return string(*a)
}

func (a *AuthMethod) Set(value string) error {
	upperAuthMethod := strings.ToUpper(value)
	*a = AuthMethod(upperAuthMethod)
	return nil
}

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
	AuthMount         string
	AuthPath          string
	K8STokenPath      string
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

	if c.AuthMethod == "" {
		val := os.Getenv("AUTH_METHOD")
		c.AuthMethod.Set(val)
	}

	switch c.AuthMethod {
	case AuthMethodK8s, AuthMethodAWS, AuthMethodGCP:
		break
	default:
		return false
	}

	// Set the default value for the authType
	if c.AuthMount == "" {
		switch c.AuthMethod {
		case AuthMethodK8s:
			c.AuthMount = "kubernetes"
		case AuthMethodAWS:
			c.AuthMount = "aws"
		case AuthMethodGCP:
			c.AuthMount = "gcp"
		}
	}

	if c.AuthPath == "" {
		c.AuthPath = fmt.Sprintf(authPathFmtString, c.AuthMount)
	}

	return true
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
