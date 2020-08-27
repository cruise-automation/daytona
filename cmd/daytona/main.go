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

	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/daytona"
)

var config cfg.Config

// this is populated at build time
var version string

func init() {
	config = cfg.DefaultConfig()

	flag.StringVar(&config.VaultAddress, "address", "", "Sets the vault server address. The default vault address or VAULT_ADDR environment variable is used if this is not supplied")
	flag.StringVar(&config.TokenPath, "token-path", config.TokenPath, "a full file path where a token will be read from/written to (env: TOKEN_PATH)")
	flag.BoolVar(&config.K8SAuth, cfg.FlagK8SAuth, config.K8SAuth, "select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)")
	flag.BoolVar(&config.AWSAuth, cfg.FlagAWSIAMAuth, config.AWSAuth, "select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)")
	flag.BoolVar(&config.AWSAuth, "iam-auth", config.AWSAuth, "(legacy) select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)")
	flag.StringVar(&config.K8STokenPath, "k8s-token-path", config.K8STokenPath, "kubernetes service account jtw token path (env: K8S_TOKEN_PATH)")
	flag.StringVar(&config.VaultAuthRoleName, "vault-auth-role", config.VaultAuthRoleName, "the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE, note: will infer to k8s sa account name if left blank)")
	flag.BoolVar(&config.GCPAuth, cfg.FlagGCPAuth, config.GCPAuth, "select Google Cloud Platform IAM auth as the vault authentication mechanism (env: GCP_AUTH)")
	flag.StringVar(&config.GCPServiceAccount, "gcp-svc-acct", config.GCPServiceAccount, "the name of the service account authenticating (env: GCP_SVC_ACCT)")
	flag.Int64Var(&config.RenewalInterval, "renewal-interval", config.RenewalInterval, "how often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL)")
	flag.Int64Var(&config.RenewalThreshold, "renewal-threshold", config.RenewalThreshold, "the threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD)")
	flag.Int64Var(&config.RenewalIncrement, "renewal-increment", config.RenewalIncrement, "the value, in seconds, to which the token's ttl should be renewed (env: RENEWAL_INCREMENT)")
	flag.StringVar(&config.SecretPayloadPath, "secret-path", config.SecretPayloadPath, "the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)")
	flag.BoolVar(&config.AutoRenew, "auto-renew", config.AutoRenew, "if enabled, starts the token renewal service (env: AUTO_RENEW)")
	flag.BoolVar(&config.Entrypoint, "entrypoint", config.Entrypoint, "if enabled, execs the command after the separator (--) when done. mostly useful with -secret-env (env: ENTRYPOINT)")
	flag.BoolVar(&config.SecretEnv, "secret-env", config.SecretEnv, "write secrets to environment variables (env: SECRET_ENV)")
	flag.BoolVar(&config.InfiniteAuth, "infinite-auth", config.InfiniteAuth, "infinitely attempt to authenticate (env: INFINITE_AUTH)")
	flag.Int64Var(&config.MaximumAuthRetry, "max-auth-duration", config.MaximumAuthRetry, "the value, in seconds, for which DAYTONA should attempt to renew a token before exiting (env: MAX_AUTH_DURATION)")
	flag.StringVar(&config.K8SAuthMount, "k8s-auth-mount", config.K8SAuthMount, "the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT, note: will infer via k8s metadata api if left unset)")
	flag.StringVar(&config.AWSAuthMount, "iam-auth-mount", config.AWSAuthMount, "the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT)")
	flag.StringVar(&config.GCPAuthMount, "gcp-auth-mount", config.GCPAuthMount, "the vault mount where gcp auth takes place (env: GCP_AUTH_MOUNT)")
	flag.StringVar(&config.AuthMount, "auth-mount", config.AuthMount, "")
	flag.IntVar(&config.Workers, "workers", config.Workers, "how many workers to run to read secrets in parallel (env: WORKERS) (Max: 5)")
	flag.StringVar(&config.PkiIssuer, "pki-issuer", config.PkiIssuer, "the name of the PKI CA backend to use when requesting a certificate (env: PKI_ISSUER)")
	flag.StringVar(&config.PkiRole, "pki-role", config.PkiRole, "the name of the PKI role to use when requesting a certificate (env: PKI_ROLE)")
	flag.StringVar(&config.PkiDomains, "pki-domains", config.PkiDomains, "a comma-separated list of domain names to use when requesting a certificate (env: PKI_DOMAINS)")
	flag.StringVar(&config.PkiPrivateKey, "pki-privkey", config.PkiPrivateKey, "a full file path where the vault-issued private key will be written to (env: PKI_PRIVKEY)")
	flag.StringVar(&config.PkiCertificate, "pki-cert", config.PkiCertificate, "a full file path where the vault-issued x509 certificate will be written to (env: PKI_CERT)")
	flag.BoolVar(&config.PkiUseCaChain, "pki-use-ca-chain", config.PkiUseCaChain, "if set, retrieve the CA chain and include it in the certificate file output (env: PKI_USE_CA_CHAIN)")

}

func main() {
	log.SetPrefix("DAYTONA - ")
	log.Printf("Starting %s...\n", version)
	flag.Parse()

	if err := daytona.Run(config, flag.Args()...); err != nil {
		log.Fatalln(err.Error())
	}
}
