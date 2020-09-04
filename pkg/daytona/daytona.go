package daytona

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cruise-automation/daytona/pkg/auth"
	cfg "github.com/cruise-automation/daytona/pkg/config"
	"github.com/cruise-automation/daytona/pkg/pki"
	"github.com/cruise-automation/daytona/pkg/secrets"
	"github.com/hashicorp/vault/api"
)

func Run(config cfg.Config, args ...string) error {
	if err := config.ValidateAndBuild(); err != nil {
		return err
	}

	vaultConfig := api.DefaultConfig()
	if config.VaultAddress != "" {
		vaultConfig.Address = config.VaultAddress
	}
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("Could not configure vault client. error: %w\n", err)
	}

	if !auth.EnsureAuthenticated(client, config) {
		return errors.New("The maximum elapsed time has been reached for authentication attempts. exiting.")
	}

	secrets.SecretFetcher(client, config)
	pki.CertFetcher(client, config)

	if config.AutoRenew {
		// if you send USR1, we'll re-fetch secrets
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGUSR1)

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
		if len(args) == 0 {
			return errors.New("No arguments detected with use of -entrypoint")
		}
		log.Println("Will exec: ", args)
		binary, err := exec.LookPath(args[0])
		if err != nil {
			return fmt.Errorf("Error finding '%s' to exec: %w\n", args[0], err)
		}
		err = syscall.Exec(binary, args, os.Environ())
		if err != nil {
			return fmt.Errorf("Error from exec: %w\n", err)
		}
	}

	return nil
}
