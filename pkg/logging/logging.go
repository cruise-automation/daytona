package logging

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// EnvLevel defines the envionrment variable name to use
// to determine the log level
const EnvLevel = "LOG_LEVEL"

// Config holds configuration items for the logger
type Config struct {
	Structured     bool
	Level          string
	LevelFieldName string
}

// Setup the logging level, level field name and output (JSON or console).
func Setup(cfg Config) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(level)
	zerolog.LevelFieldName = cfg.LevelFieldName

	var writer io.Writer = os.Stderr

	if !cfg.Structured {
		cslWriter := zerolog.NewConsoleWriter()
		cslWriter.NoColor = true
		writer = cslWriter
	}

	log.Logger = zerolog.New(writer).With().Timestamp().Str("applicationName", "daytona").Logger()
}
