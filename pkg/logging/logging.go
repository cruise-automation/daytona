package logging

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const EnvLevel = "LOG_LEVEL"

type Config struct {
	Structured     bool
	Level          string
	LevelFieldName string
}

type ErrorFilteredWriter struct {
	w zerolog.LevelWriter
}

func (w *ErrorFilteredWriter) Write(p []byte) (n int, err error) {
	return w.w.Write(p)
}

func (w *ErrorFilteredWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if level >= zerolog.ErrorLevel {
		return w.w.WriteLevel(level, p)
	}
	return len(p), nil
}

type NonErrorFilteredWriter struct {
	w zerolog.LevelWriter
}

func (w *NonErrorFilteredWriter) Write(p []byte) (n int, err error) {
	return w.w.Write(p)
}

func (w *NonErrorFilteredWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if level < zerolog.ErrorLevel {
		return w.w.WriteLevel(level, p)
	}
	return len(p), nil
}

// Setup the logging level, level field name and output (JSON or console).
func Setup(cfg Config) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(level)
	zerolog.LevelFieldName = cfg.LevelFieldName

	// Write errors and fatal errors to Stderr
	errWriter := &ErrorFilteredWriter{zerolog.MultiLevelWriter(os.Stderr)}
	// Write debug, informational, and warnings to Stdout
	nonErrWriter := &NonErrorFilteredWriter{zerolog.MultiLevelWriter(os.Stdout)}

	var writer io.Writer = zerolog.MultiLevelWriter(errWriter, nonErrWriter)

	if !cfg.Structured {
		cslWriter := zerolog.NewConsoleWriter()
		cslWriter.NoColor = true
		writer = cslWriter
	}

	log.Logger = zerolog.New(writer).With().Timestamp().Str("applicationName", "daytona").Logger()
}
