/*
   Copyright 2019-present, Cruise LLC

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
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
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

	sigChan       chan os.Signal
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

		sigChan:       make(chan os.Signal),
		keyPathInChan: make(chan string),
		secretOutChan: make(chan *SecretResult),
	}

	signal.Notify(parallelReader.sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-parallelReader.sigChan
		parallelReader.cancelFunc()
	}()

	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		go parallelReader.worker(i + 1)
	}

	return parallelReader
}

// ReadPaths processes all of the paths for the provided
// secret definition
func (pr *ParallelReader) ReadPaths(def *SecretDefinition) error {
	done := make(chan bool)
	errChan := make(chan error)

	go func() {
		for _, path := range def.paths {
			pr.keyPathInChan <- path
		}
	}()

	go func() {
		for range def.paths {
			result := <-pr.secretOutChan
			err := def.addSecrets(result)
			if err != nil {
				errChan <- err
				return
			}
		}
		done <- true
	}()

	for {
		select {
		case err := <-errChan:
			return err
		case <-done:
			return nil
		case <-pr.ctx.Done():
			return pr.ctx.Err()
		}
	}
}

// Close stops the workers
func (pr *ParallelReader) Close() {
	pr.cancelFunc()
}

func (pr *ParallelReader) worker(id int) {
	log.Trace().Int("worker_id", id).Msg("starting worker")

	for {
		select {
		case <-pr.ctx.Done():
			log.Trace().Int("worker_id", id).Msg("shutting down worker")
			return
		case keyPath := <-pr.keyPathInChan:
			log.Trace().Int("worker_id", id).
				Str("path", keyPath).Msg("reading vault path")
			secret, err := pr.logicalClient.Read(keyPath)
			pr.secretOutChan <- &SecretResult{
				KeyPath: keyPath,
				Secret:  secret,
				Err:     err,
			}
		}
	}
}
