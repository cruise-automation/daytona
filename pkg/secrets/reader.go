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

	"github.com/hashicorp/vault/api"
)

// LogicalClient is the minimum interface needed to read secrets from the API
type LogicalClient interface {
	Read(string) (*api.Secret, error)
}

// SecretResult is the output of reading a secret
type SecretResult struct {
	KeyPath string
	Secret  *api.Secret
	Err     error
}

// ParallelReader allows for processing vault read requests in parallel with n workers
type ParallelReader struct {
	ctx        context.Context
	cancelFunc func()

	logicalClient LogicalClient
	keyPathInChan chan string
	secretOutChan chan *SecretResult
}

// NewParallelReader returns an instance of ParallelReader and starts n workers
func NewParallelReader(ctx context.Context, logicalClient LogicalClient, numWorkers int) *ParallelReader {
	ctx, cancelFunc := context.WithCancel(ctx)

	parallelReader := &ParallelReader{
		ctx:        ctx,
		cancelFunc: cancelFunc,

		logicalClient: logicalClient,

		keyPathInChan: make(chan string, 100),
		secretOutChan: make(chan *SecretResult, 100),
	}

	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		go parallelReader.worker()
	}

	return parallelReader
}

// AsyncRequestKeyPath adds on a key path to read to the queue
func (pr *ParallelReader) AsyncRequestKeyPath(keyPath string) {
	pr.keyPathInChan <- keyPath
}

// ReadSecretResult blocks until a finished secret result is returned
func (pr *ParallelReader) ReadSecretResult() *SecretResult {
	return <-pr.secretOutChan
}

// Close stops the workers
func (pr *ParallelReader) Close() {
	pr.cancelFunc()
}

func (pr *ParallelReader) worker() {
	for {
		select {
		case <-pr.ctx.Done():
			return
		case keyPath := <-pr.keyPathInChan:
			secret, err := pr.logicalClient.Read(keyPath)
			pr.secretOutChan <- &SecretResult{
				KeyPath: keyPath,
				Secret:  secret,
				Err:     err,
			}
		}
	}
}