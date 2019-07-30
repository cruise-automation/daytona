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

package secrets

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

type TestParameters struct {
	NumKeys    int
	NumWorkers int
	Err        error
}

func TestParallelReader(t *testing.T) {
	tests := []TestParameters{
		TestParameters{
			NumKeys:    0,
			NumWorkers: 1,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    1,
			NumWorkers: 1,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    5,
			NumWorkers: 1,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    2,
			NumWorkers: 2,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    1,
			NumWorkers: 2,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    5,
			NumWorkers: 5,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    0,
			NumWorkers: 5,
			Err:        nil,
		},
		TestParameters{
			NumKeys:    5,
			NumWorkers: 5,
			Err:        fmt.Errorf("mock error"),
		},
	}

	for _, testParameters := range tests {
		testParallelReadIteration(t, testParameters)
	}
}

func testParallelReadIteration(t *testing.T, testParameters TestParameters) {
	expectedSecretResults := getExpectedSecretResults(testParameters)

	ctx := context.Background()
	logicalClient := &MockLogicalClient{
		FakeErr: testParameters.Err,
	}

	parallelReader := NewParallelReader(ctx, logicalClient, testParameters.NumWorkers)
	defer parallelReader.Close()

	for i := 0; i < testParameters.NumKeys; i++ {
		parallelReader.AsyncRequestKeyPath(fmt.Sprintf("fake/path/key%d", i))
	}

	secrets := make([]*SecretResult, 0)
	for i := 0; i < testParameters.NumKeys; i++ {
		secrets = append(secrets, parallelReader.ReadSecretResult())
	}

	assert.Equal(t, len(secrets), testParameters.NumKeys)
	assert.ElementsMatch(t, secrets, expectedSecretResults)
}

func getExpectedSecretResults(testParameters TestParameters) []*SecretResult {
	secretResults := make([]*SecretResult, 0)
	for i := 0; i < testParameters.NumKeys; i++ {
		secret := &api.Secret{
			RequestID: fmt.Sprintf("abc%d", i),

			LeaseID:       "abc",
			LeaseDuration: 600,
			Renewable:     true,

			Data: map[string]interface{}{
				"key": fmt.Sprintf("def%d", i),
			},

			Warnings: []string{},
		}

		secretResult := &SecretResult{
			KeyPath: fmt.Sprintf("fake/path/key%d", i),
			Secret:  secret,
			Err:     testParameters.Err,
		}

		secretResults = append(secretResults, secretResult)
	}

	return secretResults
}

// MockLogicalClient is an implementation that satisfies LogicalClient interface
type MockLogicalClient struct {
	iteration int
	mutex     sync.Mutex

	FakeErr error
}

// Read returns a mock secret response for a given path
func (m *MockLogicalClient) Read(path string) (*api.Secret, error) {
	m.mutex.Lock()
	iteration := m.iteration
	m.iteration++
	m.mutex.Unlock()

	return &api.Secret{
		RequestID: fmt.Sprintf("abc%d", iteration),

		LeaseID:       "abc",
		LeaseDuration: 600,
		Renewable:     true,

		Data: map[string]interface{}{
			"key": fmt.Sprintf("def%d", iteration),
		},

		Warnings: []string{},
	}, m.FakeErr
}
