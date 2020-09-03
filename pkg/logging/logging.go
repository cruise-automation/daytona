package logging

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const envLogLevel = "LOG_LEVEL"

type Config struct {
	Level          Level
	LevelFieldName string
	Structured     bool
}

type Level struct {
	zerolog.Level
}

// Set the level using level or LOG_LEVEL environment variable
// return an error if the level cannot be parsed
func (l *Level) Set(level string) error {
	if level == "" {
		level = os.Getenv(envLogLevel)
	}

	var err error
	l.Level, err = zerolog.ParseLevel(level)

	return err
}

// Setup the logging level, level field name and output (JSON or console)
func Setup(cfg Config) {
	zerolog.SetGlobalLevel(cfg.Level.Level)
	zerolog.LevelFieldName = cfg.LevelFieldName

	var writer io.Writer = os.Stderr
	if !cfg.Structured {
		cslWriter := zerolog.NewConsoleWriter()
		cslWriter.NoColor = true
		writer = cslWriter
	}

	log.Logger = zerolog.New(writer).With().Timestamp().Str("applicationName", "daytona").Logger()
}
