/*
Copyright 2019 GM Cruise LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cruise-automation/daytona/pkg/auth"
	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/logging"
	"github.com/cruise-automation/daytona/pkg/pki"
	"github.com/cruise-automation/daytona/pkg/secrets"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var config cfg.Config

// this is populated at build time
var version string

func init() {
	flag.Var(&config.AuthMethod, "auth-method", "Select between AWS, GCP, or K8S as the vault authentication mechanism (env: AUTH_METHOD)")
	flag.StringVar(&config.AuthMount, "auth-mount", "", "The vault mount where auth takes place")
	flag.StringVar(&config.FullAuthMount, "full-auth-mount", "", "The complete path for auth. If not provied one will be constructed from -auth-mount")

	flag.StringVar(&config.VaultAddress, "address", "", "Sets the vault server address. The default vault address or VAULT_ADDR environment variable is used if this is not supplied")
	flag.StringVar(&config.TokenPath, "token-path", cfg.BuildDefaultConfigItem("TOKEN_PATH", "~/.vault-token"), "a full file path where a token will be read from/written to (env: TOKEN_PATH)")
	flag.StringVar(&config.K8STokenPath, "k8s-token-path", cfg.BuildDefaultConfigItem("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "kubernetes service account jtw token path (env: K8S_TOKEN_PATH)")
	flag.StringVar(&config.VaultAuthRoleName, "vault-auth-role", cfg.BuildDefaultConfigItem("VAULT_AUTH_ROLE", ""), "the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE, note: will infer to k8s sa account name if left blank)")
	flag.StringVar(&config.GCPServiceAccount, "gcp-svc-acct", cfg.BuildDefaultConfigItem("GCP_SVC_ACCT", ""), "the name of the service account authenticating (env: GCP_SVC_ACCT)")
	flag.Int64Var(&config.RenewalInterval, "renewal-interval", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("RENEWAL_INTERVAL", "300"), 10, 64)
		if err != nil {
			return 900
		}
		return b
	}(), "How often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL)")
	flag.Int64Var(&config.RenewalThreshold, "renewal-threshold", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("RENEWAL_THRESHOLD", "7200"), 10, 64)
		if err != nil {
			return 7200
		}
		return b
	}(), "The threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD)")
	flag.Int64Var(&config.RenewalIncrement, "renewal-increment", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("RENEWAL_INCREMENT", "43200"), 10, 64)
		if err != nil {
			return 43200
		}
		return b
	}(), "The value, in seconds, to which the token's ttl should be renewed (env: RENEWAL_INCREMENT)")
	flag.StringVar(&config.SecretPayloadPath, "secret-path", cfg.BuildDefaultConfigItem("SECRET_PATH", ""), "The full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)")
	flag.BoolVar(&config.AutoRenew, "auto-renew", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("AUTO_RENEW", "false"))
		return err == nil && b
	}(), "If enabled, starts the token renewal service (env: AUTO_RENEW)")
	flag.BoolVar(&config.Entrypoint, "entrypoint", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("ENTRYPOINT", "false"))
		return err == nil && b
	}(), "If enabled, execs the command after the separator (--) when done. Mostly useful with -secret-env (env: ENTRYPOINT)")
	flag.BoolVar(&config.SecretEnv, "secret-env", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("SECRET_ENV", "false"))
		return err == nil && b
	}(), "Write secrets to environment variables (env: SECRET_ENV)")
	flag.BoolVar(&config.InfiniteAuth, "infinite-auth", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("INFINITE_AUTH", "false"))
		return err == nil && b
	}(), "Infinitely attempt to authenticate (env: INFINITE_AUTH)")
	flag.Int64Var(&config.MaximumAuthRetry, "max-auth-duration", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("MAX_AUTH_DURATION", "300"), 10, 64)
		if err != nil {
			return 300
		}
		return b
	}(), "the value, in seconds, for which DAYTONA should attempt to renew a token before exiting (env: MAX_AUTH_DURATION)")
	flag.IntVar(&config.Workers, "workers", func() int {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("WORKERS", "1"), 10, 64)
		if err != nil {
			log.Fatal().Msg("WORKERS environment variable must be a valid value")
		}

		if b < 1 || b > 5 {
			log.Fatal().Msg("-workers must be greater than zero and less than 5")
		}
		return int(b)
	}(), "How many workers to run to read secrets in parallel (env: WORKERS) (Max: 5)")
	flag.StringVar(&config.PkiIssuer, "pki-issuer", cfg.BuildDefaultConfigItem("PKI_ISSUER", ""), "The name of the PKI CA backend to use when requesting a certificate (env: PKI_ISSUER)")
	flag.StringVar(&config.PkiRole, "pki-role", cfg.BuildDefaultConfigItem("PKI_ROLE", ""), "The name of the PKI role to use when requesting a certificate (env: PKI_ROLE)")
	flag.StringVar(&config.PkiDomains, "pki-domains", cfg.BuildDefaultConfigItem("PKI_DOMAINS", ""), "A comma-separated list of domain names to use when requesting a certificate (env: PKI_DOMAINS)")
	flag.StringVar(&config.PkiPrivateKey, "pki-privkey", cfg.BuildDefaultConfigItem("PKI_PRIVKEY", ""), "A full file path where the vault-issued private key will be written to (env: PKI_PRIVKEY)")
	flag.StringVar(&config.PkiCertificate, "pki-cert", cfg.BuildDefaultConfigItem("PKI_CERT", ""), "A full file path where the vault-issued x509 certificate will be written to (env: PKI_CERT)")
	flag.BoolVar(&config.PkiUseCaChain, "pki-use-ca-chain", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("PKI_USE_CA_CHAIN", "false"))
		return err == nil && b
	}(), "If set, retrieve the CA chain and include it in the certificate file output (env: PKI_USE_CA_CHAIN)")
	flag.StringVar(&config.Log.Level, "log-level", cfg.BuildDefaultConfigItem(logging.EnvLevel, "debug"), "Defines log levels ('trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic', '') (env: "+logging.EnvLevel+")")
	flag.StringVar(&config.Log.LevelFieldName, "log-level-field-name", cfg.BuildDefaultConfigItem("LOG_LEVEL_FIELD_NAME", zerolog.LevelFieldName), "The field name used for the level field (env: LOG_LEVEL_FIELD_NAME)")
	flag.BoolVar(&config.Log.Structured, "log-structured", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("LOG_STRUCTURED", "true"))
		return err == nil && b
	}(), "If set, log output will be JSON else writes human-friendly format (env: LOG_STRUCTURED)")
}

func main() {
	flag.Parse()
	logging.Setup(config.Log)
	log.Info().Str("version", version).Msg("Starting...")

	if !config.ValidateAuthType() {
		log.Fatal().Strs("authMethods", []string{string(cfg.AuthMethodK8s), string(cfg.AuthMethodAWS), string(cfg.AuthMethodGCP)}).Msg("You must provide an auth method")
	}

	if err := config.ValidateConfig(); err != nil {
		log.Fatal().Err(err).Msg("Invalid configuration. Exiting.")
	}

	fullTokenPath, err := homedir.Expand(config.TokenPath)
	if err != nil {
		log.Warn().Str("tokenPath", config.TokenPath).Msg("Could not expand token path. Using path as-is.")
	} else {
		config.TokenPath = fullTokenPath
	}

	if f, err := os.Stat(config.TokenPath); err == nil && f.IsDir() {
		log.Warn().Msg("The provided token path is a directory, automatically appending .vault-token filename")

		config.TokenPath = filepath.Join(config.TokenPath, ".vault-token")
	}

	// =========================================================================
	// Read in configuration
	// =========================================================================
	vaultConfig := api.DefaultConfig()

	// Set the MaxRetries for rate-limited requests to a higher default, but allow
	// users to override this default by using the VAULT_MAX_RETRIES env var
	vaultConfig.MaxRetries = 5

	if err := vaultConfig.ReadEnvironment(); err != nil {
		log.Warn().Msgf("Error returned from Vault ReadEnvironment: %s", err.Error())
	}

	if config.VaultAddress != "" {
		vaultConfig.Address = config.VaultAddress
	}

	// Create a new Vault client
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not configure vault client. Exiting.")
	}

	if !auth.EnsureAuthenticated(client, config) {
		log.Fatal().Msg("The maximum elapsed time has been reached for authentication attempts. Exiting.")
	}

	// Attempt to fetch secrets
	secrets.SecretFetcher(client, config)

	// Attempt to fetch certs
	pki.CertFetcher(client, config)

	// Create channel for re-authentication
	if config.AutoRenew {
		// if you send USR1, we'll re-fetch secrets
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan,
			syscall.SIGUSR1)

		go func() {
			for {
				s := <-sigChan
				switch s {
				case syscall.SIGUSR1:
					secrets.SecretFetcher(client, config)
					pki.CertFetcher(client, config)
				}
			}
		}()
		auth.RenewService(client, config)
	}

	// Execute commands if passed into the CLI
	if config.Entrypoint {
		args := flag.Args()
		if len(args) == 0 {
			log.Fatal().Msg("No arguments detected with use of -entrypoint. Exiting.")
		}

		log.Info().Strs("args", args).Msg("Will exec")

		binary, err := exec.LookPath(args[0])
		if err != nil {
			log.Fatal().Err(err).Str("binary", args[0]).Msg("Unable to find binary to exec. Exiting.")
		}

		err = syscall.Exec(binary, args, os.Environ())
		if err != nil {
			log.Fatal().Err(err).Msg("Error from exec. Exiting.")
		}
	}
}
