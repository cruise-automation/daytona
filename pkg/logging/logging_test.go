package logging_test

import (
	"testing"

	. "github.com/cruise-automation/daytona/pkg/logging"
)

func TestSetup(t *testing.T) {
	Setup(Config{Structured: false, Level: "ThisIsNotALevel"})
	Setup(Config{Structured: false})
	Setup(Config{Structured: true})
}
