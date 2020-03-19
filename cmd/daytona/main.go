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
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cruise-automation/daytona/pkg/auth"
	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/pki"
	"github.com/cruise-automation/daytona/pkg/secrets"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

var config cfg.Config

// this is populated at build time
var version string

func init() {
	flag.StringVar(&config.VaultAddress, "address", "", "Sets the vault server address. The default vault address or VAULT_ADDR environment variable is used if this is not supplied")
	flag.StringVar(&config.TokenPath, "token-path", cfg.BuildDefaultConfigItem("TOKEN_PATH", "~/.vault-token"), "a full file path where a token will be read from/written to (env: TOKEN_PATH)")
	flag.BoolVar(&config.K8SAuth, "k8s-auth", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("K8S_AUTH", "false"))
		return err == nil && b
	}(), "select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)")
	flag.BoolVar(&config.AWSAuth, "aws-auth", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("IAM_AUTH", "false"))
		return err == nil && b
	}(), "select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)")
	flag.BoolVar(&config.AWSAuth, "iam-auth", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("IAM_AUTH", "false"))
		return err == nil && b
	}(), "(legacy) select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)")
	flag.StringVar(&config.K8STokenPath, "k8s-token-path", cfg.BuildDefaultConfigItem("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "kubernetes service account jtw token path (env: K8S_TOKEN_PATH)")
	flag.StringVar(&config.VaultAuthRoleName, "vault-auth-role", cfg.BuildDefaultConfigItem("VAULT_AUTH_ROLE", ""), "the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE, note: will infer to k8s sa account name if left blank)")
	flag.BoolVar(&config.GCPAuth, "gcp-auth", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("GCP_AUTH", "false"))
		return err == nil && b
	}(), "select Google Cloud Platform IAM auth as the vault authentication mechanism (env: GCP_AUTH)")
	flag.StringVar(&config.GCPServiceAccount, "gcp-svc-acct", cfg.BuildDefaultConfigItem("GCP_SVC_ACCT", ""), "the name of the service account authenticating (env: GCP_SVC_ACCT)")
	flag.Int64Var(&config.RenewalInterval, "renewal-interval", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("RENEWAL_INTERVAL", "300"), 10, 64)
		if err != nil {
			return 900
		}
		return b
	}(), "how often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL)")
	flag.Int64Var(&config.RenewalThreshold, "renewal-threshold", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("RENEWAL_THRESHOLD", "7200"), 10, 64)
		if err != nil {
			return 7200
		}
		return b
	}(), "the threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD)")
	flag.Int64Var(&config.RenewalIncrement, "renewal-increment", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("RENEWAL_INCREMENT", "43200"), 10, 64)
		if err != nil {
			return 43200
		}
		return b
	}(), "the value, in seconds, to which the token's ttl should be renewed (env: RENEWAL_INCREMENT)")
	flag.StringVar(&config.SecretPayloadPath, "secret-path", cfg.BuildDefaultConfigItem("SECRET_PATH", ""), "the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)")
	flag.BoolVar(&config.AutoRenew, "auto-renew", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("AUTO_RENEW", "false"))
		return err == nil && b
	}(), "if enabled, starts the token renewal service (env: AUTO_RENEW)")
	flag.BoolVar(&config.Entrypoint, "entrypoint", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("ENTRYPOINT", "false"))
		return err == nil && b
	}(), "if enabled, execs the command after the separator (--) when done. mostly useful with -secret-env (env: ENTRYPOINT)")
	flag.BoolVar(&config.SecretEnv, "secret-env", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("SECRET_ENV", "false"))
		return err == nil && b
	}(), "write secrets to environment variables (env: SECRET_ENV)")
	flag.BoolVar(&config.InfiniteAuth, "infinite-auth", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("INFINITE_AUTH", "false"))
		return err == nil && b
	}(), "infinitely attempt to authenticate (env: INFINITE_AUTH)")
	flag.Int64Var(&config.MaximumAuthRetry, "max-auth-duration", func() int64 {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("MAX_AUTH_DURATION", "300"), 10, 64)
		if err != nil {
			return 300
		}
		return b
	}(), "the value, in seconds, for which DAYTONA should attempt to renew a token before exiting (env: MAX_AUTH_DURATION)")
	flag.StringVar(&config.K8SAuthMount, "k8s-auth-mount", cfg.BuildDefaultConfigItem("K8S_AUTH_MOUNT", "kubernetes"), "the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT, note: will infer via k8s metadata api if left unset)")
	flag.StringVar(&config.AWSAuthMount, "iam-auth-mount", cfg.BuildDefaultConfigItem("IAM_AUTH_MOUNT", "aws"), "the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT)")
	flag.StringVar(&config.GCPAuthMount, "gcp-auth-mount", cfg.BuildDefaultConfigItem("GCP_AUTH_MOUNT", "gcp"), "the vault mount where gcp auth takes place (env: GCP_AUTH_MOUNT)")
	flag.StringVar(&config.AuthMount, "auth-mount", cfg.BuildDefaultConfigItem("AUTH_MOUNT", ""), "")
	flag.IntVar(&config.Workers, "workers", func() int {
		b, err := strconv.ParseInt(cfg.BuildDefaultConfigItem("WORKERS", "1"), 10, 64)
		if err != nil {
			log.Fatal("WORKERS environment variable must be a valid value")
		}

		if b < 1 || b > 5 {
			log.Fatal("-workers must be greater than zero and less than 5")
		}
		return int(b)
	}(), "how many workers to run to read secrets in parallel (env: WORKERS) (Max: 5)")
	flag.StringVar(&config.PkiIssuer, "pki-issuer", cfg.BuildDefaultConfigItem("PKI_ISSUER", ""), "the name of the PKI CA backend to use when requesting a certificate (env: PKI_ISSUER)")
	flag.StringVar(&config.PkiRole, "pki-role", cfg.BuildDefaultConfigItem("PKI_ROLE", ""), "the name of the PKI role to use when requesting a certificate (env: PKI_ROLE)")
	flag.StringVar(&config.PkiDomains, "pki-domains", cfg.BuildDefaultConfigItem("PKI_DOMAINS", ""), "a comma-separated list of domain names to use when requesting a certificate (env: PKI_DOMAINS)")
	flag.StringVar(&config.PkiPrivateKey, "pki-privkey", cfg.BuildDefaultConfigItem("PKI_PRIVKEY", ""), "a full file path where the vault-issued private key will be written to (env: PKI_PRIVKEY)")
	flag.StringVar(&config.PkiCertificate, "pki-cert", cfg.BuildDefaultConfigItem("PKI_CERT", ""), "a full file path where the vault-issued x509 certificate will be written to (env: PKI_CERT)")
	flag.BoolVar(&config.PkiUseCaChain, "pki-use-ca-chain", func() bool {
		b, err := strconv.ParseBool(cfg.BuildDefaultConfigItem("PKI_USE_CA_CHAIN", "false"))
		return err == nil && b
	}(), "if set, retrieve the CA chain and include it in the certificate file output (env: PKI_USE_CA_CHAIN)")
}

func main() {
	log.SetPrefix("DAYTONA - ")
	log.Printf("Starting %s...\n", version)
	flag.Parse()

	if !config.ValidateAuthType() {
		log.Fatal("You must provide an auth method: -k8s-auth or -aws-iam-auth or -gcp-auth")
	}

	switch {
	case config.K8SAuth:
		auth.InferK8SConfig(&config)
		config.BuildAuthMountPath(config.K8SAuthMount)
	case config.AWSAuth:
		config.BuildAuthMountPath(config.AWSAuthMount)
	case config.GCPAuth:
		config.BuildAuthMountPath(config.GCPAuthMount)
	}

	if err := config.ValidateConfig(); err != nil {
		log.Fatalln(err.Error())
	}

	fullTokenPath, err := homedir.Expand(config.TokenPath)
	if err != nil {
		log.Println("Could not expand", config.TokenPath, "using it as-is")
	} else {
		config.TokenPath = fullTokenPath
	}
	if f, err := os.Stat(config.TokenPath); err == nil && f.IsDir() {
		log.Println("The provided token path is a directory, automatically appending .vault-token filename")
		config.TokenPath = filepath.Join(config.TokenPath, ".vault-token")
	}

	vaultConfig := api.DefaultConfig()
	if config.VaultAddress != "" {
		vaultConfig.Address = config.VaultAddress
	}
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Could not configure vault client. error: %s\n", err)
	}

	if !auth.EnsureAuthenticated(client, config) {
		log.Fatalln("The maximum elapsed time has been reached for authentication attempts. exiting.")
	}

	secrets.SecretFetcher(client, config)
	pki.CertFetcher(client, config)

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

	if config.Entrypoint {
		args := flag.Args()
		if len(args) == 0 {
			log.Fatalln("No arguments detected with use of -entrypoint")
		}
		log.Println("Will exec: ", args)
		binary, err := exec.LookPath(args[0])
		if err != nil {
			log.Fatalf("Error finding '%s' to exec: %s\n", args[0], err)
		}
		err = syscall.Exec(binary, args, os.Environ())
		if err != nil {
			log.Fatalf("Error from exec: %s\n", err)
		}
	}
}
