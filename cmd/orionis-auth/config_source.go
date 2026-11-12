package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var defaultConfigPaths = []string{
	"config/orionis.yaml",
	"config/orionis.yml",
	"config/orionis.json",
	"config/orionis.example.yaml",
	"config/orionis.example.json",
}

func selectConfigSource(flagPath string, flagSet bool, envPath, root string) (string, error) {
	if flagSet {
		if strings.TrimSpace(flagPath) == "" {
			return "", errors.New("config path is required")
		}

		return flagPath, nil
	}

	if strings.TrimSpace(envPath) != "" {
		return envPath, nil
	}

	for _, candidate := range defaultConfigPaths {
		path := filepath.Join(root, candidate)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect config %q: %w", path, err)
		}
	}

	return "", fmt.Errorf(
		"no Orionis config found (checked %s); set -config or ORIONIS_CONFIG",
		strings.Join(defaultConfigPaths, ", "),
	)
}
