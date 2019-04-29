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
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

var config struct {
	vaultAddress      string
	tokenPath         string
	k8sTokenPath      string
	k8sAuth           bool
	k8sAuthMount      string
	iamAuth           bool
	iamAuthMount      string
	gcpIAMAuth        bool
	gcpAuthMount      string
	gcpServiceAccount string
	vaultAuthRoleName string
	renewalThreshold  int64
	renewalIncrement  int64
	renewalInterval   int64
	secretPayloadPath string
	secretEnv         bool
	autoRenew         bool
	entrypoint        bool
	infiniteAuth      bool
	maximumAuthRetry  int64
	authMount         string
}

const defaultKeyName = "value"
const version = "0.0.3"
const secretLocationPrefix = "DAYTONA_SECRET_DESTINATION_"
const authPathFmtString = "auth/%s/login"

// buildDefaultConfigItem uses the following operation: ENV --> arg
func buildDefaultConfigItem(envKey string, def string) (val string) {
	val = os.Getenv(envKey)
	if val == "" {
		val = def
	}
	return
}

func init() {
	flag.StringVar(&config.vaultAddress, "address", buildDefaultConfigItem("VAULT_ADDR", "https://vault.company.com:8200"), "(env: VAULT_ADDR)")
	flag.StringVar(&config.tokenPath, "token-path", buildDefaultConfigItem("TOKEN_PATH", "~/.vault-token"), "a full file path where a token will be read from/written to (env: TOKEN_PATH)")
	flag.BoolVar(&config.k8sAuth, "k8s-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("K8S_AUTH", "false"))
		return err == nil && b
	}(), "select kubernetes vault auth as the vault authentication mechanism (env: K8S_AUTH)")
	flag.BoolVar(&config.iamAuth, "iam-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("IAM_AUTH", "false"))
		return err == nil && b
	}(), "select AWS IAM vault auth as the vault authentication mechanism (env: IAM_AUTH)")
	flag.StringVar(&config.k8sTokenPath, "k8s-token-path", buildDefaultConfigItem("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"), "kubernetes service account jtw token path (env: K8S_TOKEN_PATH)")
	flag.StringVar(&config.vaultAuthRoleName, "vault-auth-role", buildDefaultConfigItem("VAULT_AUTH_ROLE", ""), "the name of the role used for auth. used with either auth method (env: VAULT_AUTH_ROLE, note: will infer to k8s sa account name if left blank)")
	flag.BoolVar(&config.gcpIAMAuth, "gcp-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("GCP_AUTH", "false"))
		return err == nil && b
	}(), "select Google Cloud Platform IAM auth as the vault authentication mechanism (env: GCP_AUTH)")
	flag.StringVar(&config.gcpServiceAccount, "gcp-svc-acct", buildDefaultConfigItem("GCP_SVC_ACCT", ""), "the name of the service account authenticating (env: GCP_SVC_ACCT)")
	flag.Int64Var(&config.renewalInterval, "renewal-interval", func() int64 {
		b, err := strconv.ParseInt(buildDefaultConfigItem("RENEWAL_INTERVAL", "300"), 10, 64)
		if err != nil {
			return 900
		}
		return b
	}(), "how often to check the token's ttl and potentially renew it (env: RENEWAL_INTERVAL)")
	flag.Int64Var(&config.renewalThreshold, "renewal-threshold", func() int64 {
		b, err := strconv.ParseInt(buildDefaultConfigItem("RENEWAL_THRESHOLD", "7200"), 10, 64)
		if err != nil {
			return 7200
		}
		return b
	}(), "the threshold remaining in the vault token, in seconds, after which it should be renewed (env: RENEWAL_THRESHOLD)")
	flag.Int64Var(&config.renewalIncrement, "renewal-increment", func() int64 {
		b, err := strconv.ParseInt(buildDefaultConfigItem("RENEWAL_INCREMENT", "43200"), 10, 64)
		if err != nil {
			return 43200
		}
		return b
	}(), "the value, in seconds, to which the token's ttl should be renewed (env: RENEWAL_INCREMENT)")
	flag.StringVar(&config.secretPayloadPath, "secret-path", buildDefaultConfigItem("SECRET_PATH", ""), "the full file path to store the JSON blob of the fetched secrets (env: SECRET_PATH)")
	flag.BoolVar(&config.autoRenew, "auto-renew", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("AUTO_RENEW", "false"))
		return err == nil && b
	}(), "if enabled, starts the token renewal service (env: AUTO_RENEW)")
	flag.BoolVar(&config.entrypoint, "entrypoint", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("ENTRYPOINT", "false"))
		return err == nil && b
	}(), "if enabled, execs the command after the separator (--) when done. mostly useful with -secret-env (env: ENTRYPOINT)")
	flag.BoolVar(&config.secretEnv, "secret-env", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("SECRET_ENV", "false"))
		return err == nil && b
	}(), "write secrets to environment variables (env: SECRET_ENV)")
	flag.BoolVar(&config.infiniteAuth, "infinite-auth", func() bool {
		b, err := strconv.ParseBool(buildDefaultConfigItem("INFINITE_AUTH", "false"))
		return err == nil && b
	}(), "infinitely attempt to authenticate (env: INFINITE_AUTH)")
	flag.Int64Var(&config.maximumAuthRetry, "max-auth-duration", func() int64 {
		b, err := strconv.ParseInt(buildDefaultConfigItem("MAX_AUTH_DURATION", "300"), 10, 64)
		if err != nil {
			return 300
		}
		return b
	}(), "the value, in seconds, for which DAYTONA should attempt to renew a token before exiting (env: MAX_AUTH_DURATION)")

	flag.StringVar(&config.k8sAuthMount, "k8s-auth-mount", buildDefaultConfigItem("K8S_AUTH_MOUNT", "kubernetes"), "the vault mount where k8s auth takes place (env: K8S_AUTH_MOUNT, note: will infer via k8s metadata api if left unset)")
	flag.StringVar(&config.iamAuthMount, "iam-auth-mount", buildDefaultConfigItem("IAM_AUTH_MOUNT", "aws"), "the vault mount where iam auth takes place (env: IAM_AUTH_MOUNT)")
	flag.StringVar(&config.gcpAuthMount, "gcp-auth-mount", buildDefaultConfigItem("GCP_AUTH_MOUNT", "gcp"), "the vault mount where gcp auth takes place (env: GCP_AUTH_MOUNT)")
	flag.StringVar(&config.authMount, "auth-mount", buildDefaultConfigItem("AUTH_MOUNT", ""), "")
}

func main() {
	log.SetPrefix("DAYTONA - ")
	flag.Parse()

	err := validateConfig()
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case config.k8sAuth:
		InferK8SConfig()
	case config.iamAuth:
	case config.gcpIAMAuth:
	}

	if config.authMount == "" {
		switch {
		case config.k8sAuth:
			config.authMount = fmt.Sprintf(authPathFmtString, config.k8sAuthMount)
		case config.iamAuth:
			config.authMount = fmt.Sprintf(authPathFmtString, config.iamAuthMount)
		case config.gcpIAMAuth:
			config.authMount = fmt.Sprintf(authPathFmtString, config.gcpAuthMount)
		}
	}

	fullTokenPath, err := homedir.Expand(config.tokenPath)
	if err != nil {
		log.Println("Could not expand", config.tokenPath, "using it as-is")
	} else {
		config.tokenPath = fullTokenPath
	}
	if f, err := os.Stat(config.tokenPath); err == nil && f.IsDir() {
		log.Println("The provided token path is a directory, automatically appending .vault-token filename")
		config.tokenPath = filepath.Join(config.tokenPath, ".vault-token")
	}

	if config.secretPayloadPath != "" {
		if f, err := os.Stat(config.secretPayloadPath); err == nil && f.IsDir() {
			log.Fatalln("The secret path you provided is a directory, please supply a full file path")
		}
	}

	log.Printf("Starting DAYTONA v%s\n", version)
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.vaultAddress
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Could not configure vault client. error: %s\n", err)
	}

	if !ensureAuthenticated(client) {
		log.Fatalln("The maximum elapsed time has been reached for authentication attempts. exiting.")
	}

	secretFetcher(client)
	if config.autoRenew {
		// if you send USR1, we'll re-fetch secrets
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan,
			syscall.SIGUSR1)

		go func() {
			for {
				s := <-sigChan
				switch s {
				case syscall.SIGUSR1:
					secretFetcher(client)
				}
			}
		}()
		renewService(client, (time.Second * time.Duration(config.renewalInterval)))
	}

	if config.entrypoint {
		args := flag.Args()
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

// ensureAuthentication verifies we have a valid token, or attempts to fetch a new one.
// Returns false if it is unable to become authenticated
func ensureAuthenticated(client *api.Client) bool {
	// Vault Go API will read a token from VAULT_TOKEN if it exists.
	// If it didn't find one, attempt to read token from disk.
	log.Println("Checking for an existing, valid vault token")
	if checkToken(client) {
		return true
	}

	log.Println("No token found in VAULT_TOKEN env, checking path")
	if checkFileToken(client, config.tokenPath) {
		return true
	}

	log.Printf("No token found in %q, trying to re-authenticate\n", config.tokenPath)
	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = time.Second * 15
	if config.infiniteAuth {
		log.Println("Infinite authentication enabled.")
		bo.MaxElapsedTime = 0
	} else {
		log.Printf("Authentication will be attempted for %d seconds.\n", config.maximumAuthRetry)
		bo.MaxElapsedTime = time.Second * time.Duration(config.maximumAuthRetry)
	}

	var svc ExternalService
	switch {
	case config.k8sAuth:
		svc = &K8SService{}
	case config.iamAuth:
		svc = &AWSService{}
	case config.gcpIAMAuth:
		svc = &GCPService{}
	default:
		panic("should never get here")
	}

	authTicker := backoff.NewTicker(bo)
	for range authTicker.C {
		log.Println("Attempting to authenticate")
		if authenticate(client, svc) {
			log.Println("Authenticated")
			return true
		}
	}

	return false
}

// checkToken ensures the currently set token token is valid, or unsets it.
// Returns true if the token is valid
func checkToken(client *api.Client) bool {
	if client.Token() == "" {
		return false
	}

	// Check the validity of the token.  If from disk, it could be expired.
	_, err := client.Auth().Token().LookupSelf()
	if err != nil {
		log.Println("Invalid token: ", err)
		client.ClearToken()
		return false
	}

	return true
}

// checkFileToken attempts to read a token from the specified tokenPath, and ensures it is set and valid.
// Returns false if it is unable to read the token, or the token is invalid
func checkFileToken(client *api.Client, tokenPath string) bool {
	fileToken, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		log.Printf("Can't read an existing token at %q.\n", tokenPath)
		return false
	}
	log.Println("Found an existing token at", tokenPath)
	client.SetToken(string(fileToken))

	return checkToken(client)
}

// validateConfig performs some basic validation on the provided configuration
func validateConfig() error {
	if !config.k8sAuth && !config.iamAuth && !config.gcpIAMAuth {
		return errors.New("You must provide an auth method: -k8s-auth or -iam-auth or -gcp-auth")
	}
	p := 0
	for _, v := range []bool{config.k8sAuth, config.iamAuth, config.gcpIAMAuth} {
		if v {
			p++
		}
	}
	if p > 1 {
		return errors.New("You cannot choose more than one auth method")
	}

	if config.vaultAuthRoleName == "" {
		return errors.New("You must supply a role name via VAULT_AUTH_ROLE or -vault-auth-role")
	}
	return nil
}

func renewService(client *api.Client, interval time.Duration) {
	log.Println("Starting the token renewer service on interval", interval)
	ticker := time.Tick(interval)
	for {
		result, err := client.Auth().Token().LookupSelf()
		if err != nil {
			log.Fatalln("The existing token failed renewal, exiting..")
		}
		ttl, err := result.TokenTTL()
		if ttl.Seconds() < float64(config.renewalThreshold) {
			fmt.Println("token ttl of", ttl.Seconds(), "is below threshold of", config.renewalThreshold, ", renewing to", config.renewalIncrement)
			secret, err := client.Auth().Token().RenewSelf(int(config.renewalIncrement))
			if err != nil {
				log.Println("Failed to renew the existing token:", err)
			}
			client.SetToken(string(secret.Auth.ClientToken))
			err = ioutil.WriteFile(config.tokenPath, []byte(secret.Auth.ClientToken), 0600)
			if err != nil {
				log.Println("Could not write token to file", config.tokenPath, err.Error())
			}
		} else {
			log.Printf("Existing token ttl of %d seconds is still above the threshold (%d), skipping renewal\n", int64(ttl.Seconds()), config.renewalThreshold)
		}
		<-ticker
	}
}
