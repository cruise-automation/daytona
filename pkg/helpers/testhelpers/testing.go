package testhelpers

import "github.com/hashicorp/vault/api"

func GetTestClient(url string) (*api.Client, error) {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = url
	err := vaultConfig.ConfigureTLS(&api.TLSConfig{Insecure: true})
	if err != nil {
		return nil, err
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}
