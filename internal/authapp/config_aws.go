package authapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stremovskyy/confucius"
)

const appConfigStartupTimeout = 30 * time.Second

type awsConfigOptions struct {
	region      string
	application string
	environment string
	profile     string
}

type configLoader interface {
	Load(context.Context, any) error
}

func newAWSConfigLoader(options awsConfigOptions) configLoader {
	return confucius.AWS().
		WithRegion(options.region).
		AppConfig().
		Loader(options.application, options.environment, options.profile).
		WithDecoder(configDecoder{})
}

func awsConfigOptionsFromEnv() (awsConfigOptions, error) {
	options := awsConfigOptions{region: strings.TrimSpace(os.Getenv("AWS_REGION"))}

	if options.region == "" {
		options.region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
	}

	if options.region == "" {
		options.region = "eu-central-1"
	}

	for _, field := range []struct {
		name  string
		value *string
	}{
		{"AWS_APPCONFIG_APPLICATION", &options.application},
		{"AWS_APPCONFIG_ENVIRONMENT", &options.environment},
		{"AWS_APPCONFIG_PROFILE", &options.profile},
	} {
		*field.value = strings.TrimSpace(os.Getenv(field.name))

		if *field.value == "" {
			return awsConfigOptions{}, fmt.Errorf("%s is required when -config=aws", field.name)
		}
	}

	return options, nil
}

func loadAWSConfig(ctx context.Context, factory func(awsConfigOptions) configLoader) (Config, error) {
	options, err := awsConfigOptionsFromEnv()
	if err != nil {
		return Config{}, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, appConfigStartupTimeout)
	defer cancel()

	var wire wireConfig

	if err := factory(options).Load(ctx, &wire); err != nil {
		// Provider and decoder errors can contain hosted values. Do not retain
		// their error chain or a partially decoded configuration on failure.
		return Config{}, errors.New("load config: AWS AppConfig configuration could not be loaded")
	}

	resolved, err := compileConfig(wire.runtimeConfig())
	if err != nil {
		return Config{}, errors.New("validate config: AWS AppConfig configuration is invalid")
	}

	return resolved.raw, nil
}
