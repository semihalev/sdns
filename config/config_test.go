package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_config(t *testing.T) {
	const configFile = "example.conf"

	err := generateConfig(configFile)
	assert.NoError(t, err)

	_, err = Load(configFile, "0.0.0")
	assert.NoError(t, err)

	os.Remove(configFile)
}

func Test_configError(t *testing.T) {
	const configFile = ""

	_, err := Load(configFile, "0.0.0")
	assert.Error(t, err)
}
