package authapp

import (
	"bytes"
	"encoding/json"

	"github.com/stremovskyy/confucius/decoder"
)

type configDecoder struct{}

func (configDecoder) Name() string { return "json/yaml" }

func (configDecoder) Decode(data []byte, target any, _ decoder.DecodeOptions) error {
	return decodeConfig(data, target)
}

func decodeConfig(data []byte, target any) error {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	// Prefer the existing JSON contract for complete JSON documents. A schema
	// error must not fall back to YAML and change field types or values.
	if json.Valid(data) {
		return json.Unmarshal(data, target)
	}

	// YAML also supports flow mappings, comments, and document markers. Its
	// decoder must consume exactly one whole document, as the JSON decoder does.
	return decodeYAMLConfig(data, target)
}
