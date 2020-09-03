package logging_test

import (
	"os"
	"testing"

	. "github.com/cruise-automation/daytona/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func TestLevelSet(t *testing.T) {
	const (
		trace = "trace"
		panic = "panic"
	)

	level := new(Level)

	assert.Error(t, level.Set("notAValidLevel"))

	assert.NoError(t, level.Set(panic))
	assert.Equal(t, level.String(), panic)

	assert.NoError(t, os.Setenv(EnvLevel, trace))
	assert.NoError(t, level.Set(""))
	assert.Equal(t, level.String(), trace)
	assert.NoError(t, os.Unsetenv(EnvLevel))
}

func TestSetup(t *testing.T) {
	Setup(Config{Structured: false})
	Setup(Config{Structured: true})
}
