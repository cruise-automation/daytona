package testhelpers

import "github.com/hashicorp/vault/api"

// GetTestClient returns a vault api client configured to the
// supplied url. This is intented to be used in tests
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
