package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"cloud.google.com/go/compute/metadata"
	"github.com/briankassouf/jose/jws"
	homedir "github.com/mitchellh/go-homedir"
)

const (
	FlagAWSIAMAuth = "aws-auth"
	FlagK8SAuth    = "k8s-auth"
	FlagGCPAuth    = "gcp-auth"

	authPathFmtString = "auth/%s/login"
)

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
	PkiIssuer         string
	PkiRole           string
	PkiDomains        string
	PkiPrivateKey     string
	PkiCertificate    string
	PkiUseCaChain     bool
}

// buildDefaultConfigItem uses the following operation: ENV --> arg
func buildDefaultConfigItem(envKey string, def string) (val string) {
	val = os.Getenv(envKey)
	if val == "" {
		val = def
	}
	return
}

func DefaultConfig() Config {
	var (
		err     error
		workers int64
		config  = Config{
			AWSAuthMount:      buildDefaultConfigItem("IAM_AUTH_MOUNT", "aws"),
			AuthMount:         buildDefaultConfigItem("AUTH_MOUNT", ""),
			GCPAuthMount:      buildDefaultConfigItem("GCP_AUTH_MOUNT", "gcp"),
			GCPServiceAccount: buildDefaultConfigItem("GCP_SVC_ACCT", ""),
			K8SAuthMount:      buildDefaultConfigItem("K8S_AUTH_MOUNT", "kubernetes"),
			K8STokenPath:      buildDefaultConfigItem("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
			PkiCertificate:    buildDefaultConfigItem("PKI_CERT", ""),
			PkiDomains:        buildDefaultConfigItem("PKI_DOMAINS", ""),
			PkiIssuer:         buildDefaultConfigItem("PKI_ISSUER", ""),
			PkiPrivateKey:     buildDefaultConfigItem("PKI_PRIVKEY", ""),
			PkiRole:           buildDefaultConfigItem("PKI_ROLE", ""),
			SecretPayloadPath: buildDefaultConfigItem("SECRET_PATH", ""),
			TokenPath:         buildDefaultConfigItem("TOKEN_PATH", "~/.vault-token"),
			VaultAuthRoleName: buildDefaultConfigItem("VAULT_AUTH_ROLE", ""),
		}
	)

	if workers, err = strconv.ParseInt(buildDefaultConfigItem("WORKERS", "1"), 10, 64); err == nil {
		config.Workers = int(workers)
	} else {
		log.Fatal("WORKERS environment variable must be a valid value")
	}

	if config.AutoRenew, err = strconv.ParseBool(buildDefaultConfigItem("AUTO_RENEW", "false")); err != nil {
		config.AutoRenew = false
	}

	if config.Entrypoint, err = strconv.ParseBool(buildDefaultConfigItem("ENTRYPOINT", "false")); err != nil {
		config.Entrypoint = false
	}

	if config.GCPAuth, err = strconv.ParseBool(buildDefaultConfigItem("GCP_AUTH", "false")); err != nil {
		config.GCPAuth = false
	}

	if config.AWSAuth, err = strconv.ParseBool(buildDefaultConfigItem("IAM_AUTH", "false")); err != nil {
		config.AWSAuth = false
	}

	if config.InfiniteAuth, err = strconv.ParseBool(buildDefaultConfigItem("INFINITE_AUTH", "false")); err != nil {
		config.InfiniteAuth = false
	}

	if config.MaximumAuthRetry, err = strconv.ParseInt(buildDefaultConfigItem("MAX_AUTH_DURATION", "300"), 10, 64); err != nil {
		config.MaximumAuthRetry = 300
	}

	if config.PkiUseCaChain, err = strconv.ParseBool(buildDefaultConfigItem("PKI_USE_CA_CHAIN", "false")); err != nil {
		config.PkiUseCaChain = false
	}

	if config.RenewalIncrement, err = strconv.ParseInt(buildDefaultConfigItem("RENEWAL_INCREMENT", "43200"), 10, 64); err != nil {
		config.RenewalIncrement = 43200
	}

	if config.RenewalInterval, err = strconv.ParseInt(buildDefaultConfigItem("RENEWAL_INTERVAL", "300"), 10, 64); err != nil {
		config.RenewalInterval = 900
	}

	if config.RenewalThreshold, err = strconv.ParseInt(buildDefaultConfigItem("RENEWAL_THRESHOLD", "7200"), 10, 64); err != nil {
		config.RenewalThreshold = 7200
	}

	if config.SecretEnv, err = strconv.ParseBool(buildDefaultConfigItem("SECRET_ENV", "false")); err != nil {
		config.SecretEnv = false
	}

	if config.K8SAuth, err = strconv.ParseBool(buildDefaultConfigItem("K8S_AUTH", "false")); err != nil {
		config.K8SAuth = false
	}

	return config
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
	if (c.PkiIssuer != "" || c.PkiRole != "" || c.PkiDomains != "" || c.PkiPrivateKey != "" || c.PkiCertificate != "") && (c.PkiIssuer == "" || c.PkiRole == "" || c.PkiDomains == "" || c.PkiPrivateKey == "" || c.PkiCertificate == "") {
		return errors.New("One or more required PKI signing values are missing. PKI_ISSUER: " + c.PkiIssuer + ", PKI_ROLE: " + c.PkiRole + ", PKI_DOMAINS: " + c.PkiDomains + ", PKI_PRIVKEY: " + c.PkiPrivateKey + ", PKI_CERT: " + c.PkiCertificate)
	}
	return nil
}

// inferK8SConfig attempts to replace default configuration parameters on K8S with ones inferred from the k8s environment
func (c *Config) inferK8SConfig() {
	log.Println("Attempting to automatically infer some k8s configuration data")
	if c.VaultAuthRoleName == "" {
		saName, err := c.inferVaultAuthRoleName()
		if err != nil {
			log.Printf("Unable to infer SA Name: %v\n", err)
		} else {
			c.VaultAuthRoleName = saName
		}
	}

	// Check for default value
	if c.K8SAuthMount == "kubernetes" {
		vaultAuthMount, err := inferVaultAuthMount()
		if err != nil {
			log.Printf("Unable to infer K8S Vault Auth Mount: %v\n", err)
		} else {
			c.K8SAuthMount = vaultAuthMount
		}
	}
}

// inferVaultAuthRoleName figures out the current k8s service account name, and returns it.
// This can be assumed to match a a vault role if configured properly.
func (c *Config) inferVaultAuthRoleName() (string, error) {
	data, err := ioutil.ReadFile(c.K8STokenPath)
	if err != nil {
		return "", fmt.Errorf("could not read JWT from file %s", err.Error())
	}

	jwt := bytes.TrimSpace(data)

	// Parse into JWT
	parsedJWT, err := jws.ParseJWT(jwt)
	if err != nil {
		return "", err
	}

	saName, ok := parsedJWT.Claims().Get("kubernetes.io/serviceaccount/service-account.name").(string)
	if !ok || saName == "" {
		return "", errors.New("could not parse UID from claims")
	}

	return saName, nil
}

// inferVaultAuthMount attempts to figure out where the auth path for the current k8s cluster is in vault, and return it
func inferVaultAuthMount() (string, error) {
	clusterName, err := metadata.InstanceAttributeValue("cluster-name")

	return fmt.Sprintf("kubernetes-gcp-%s", clusterName), err
}

// buildAuthMountPath attempts to construct a mount path
// if the provided one is empty
func (c *Config) buildAuthMountPath() {
	switch {
	case c.K8SAuth:
		c.inferK8SConfig()
		c.AuthMount = fmt.Sprintf(authPathFmtString, c.K8SAuthMount)
	case c.AWSAuth:
		c.AuthMount = fmt.Sprintf(authPathFmtString, c.AWSAuthMount)
	case c.GCPAuth:
		c.AuthMount = fmt.Sprintf(authPathFmtString, c.GCPAuthMount)
	}
}

func (c *Config) ValidateAndBuild() error {
	if c.Workers < 1 || c.Workers > 5 {
		return errors.New("-workers must be greater than zero and less than 5")
	}

	if !c.ValidateAuthType() {
		return fmt.Errorf("You must provide an auth method: -%s or -%s or -%s\n", FlagK8SAuth, FlagAWSIAMAuth, FlagGCPAuth)
	}

	c.buildAuthMountPath()

	if err := c.ValidateConfig(); err != nil {
		return err
	}

	fullTokenPath, err := homedir.Expand(c.TokenPath)
	if err != nil {
		log.Println("Could not expand", c.TokenPath, "using it as-is")
	} else {
		c.TokenPath = fullTokenPath
	}

	if f, err := os.Stat(c.TokenPath); err == nil && f.IsDir() {
		log.Println("The provided token path is a directory, automatically appending .vault-token filename")
		c.TokenPath = filepath.Join(c.TokenPath, ".vault-token")
	}

	return nil
}
