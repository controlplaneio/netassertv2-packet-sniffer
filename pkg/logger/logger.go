// Package logger encapsulates a Zap logger
package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New constructs a Sugared Logger that writes to stdout and
// provides human-readable timestamps
func New(version, service, environment string, outputPaths ...string) (*zap.SugaredLogger, error) {
	var config zap.Config

	switch strings.ToLower(environment) {
	case "production":
		config = zap.NewProductionConfig()
		config.DisableStacktrace = true
	default:
		config = zap.NewDevelopmentConfig()
		config.DisableStacktrace = false
	}

	config.Encoding = "console"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	config.InitialFields = map[string]any{
		"service": service,
		"version": version,
	}

	config.OutputPaths = []string{"stdout"}
	if outputPaths != nil {
		config.OutputPaths = outputPaths
	}

	log, err := config.Build(zap.WithCaller(true))
	if err != nil {
		return nil, err
	}

	return log.Sugar(), nil
}
