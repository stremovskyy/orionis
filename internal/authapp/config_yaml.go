package authapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

func decodeYAMLConfig(data []byte, target any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node

	if err := dec.Decode(&document); err != nil {
		return err
	}

	var extra yaml.Node

	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("decode trailing YAML: %w", err)
		}

		return errors.New("config must contain exactly one YAML document")
	}

	// YAML's implicit timestamps must stay literal strings, especially in client
	// credentials. Decoding them as time.Time would change their contents.
	preserveYAMLStrings(&document)
	var value any

	if err := document.Decode(&value); err != nil {
		return err
	}

	// Reuse JSON field names, scalar types, and presence semantics for every
	// nested config type, including server.Client.
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return json.Unmarshal(raw, target)
}

func preserveYAMLStrings(node *yaml.Node) {
	if node.Tag == "!!timestamp" {
		node.Tag = "!!str"
	}

	for _, child := range node.Content {
		preserveYAMLStrings(child)
	}
}
