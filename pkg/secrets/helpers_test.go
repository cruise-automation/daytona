package secrets

import (
	"io/ioutil"
	"os"
	"testing"

	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

func startVaultTestCluster(t *testing.T) (*vault.TestCluster, *api.Client) {
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv": kv.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})

	cluster.Start()

	core := cluster.Cores[0]
	vault.TestWaitActive(t, core.Core)
	client := core.Client

	err := client.Sys().Mount("kv", &api.MountInput{
		Type: "kv-v2",
	})
	if err != nil {
		t.Fatal(err)
	}

	return cluster, client
}

func generateTestFile(prefix string) (*os.File, error) {
	file, err := ioutil.TempFile(os.TempDir(), prefix)
	if err != nil {
		return nil, err
	}
	return file, nil
}
