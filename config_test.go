package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_config(t *testing.T) {
	const configFile = "temp.toml"

	err := generateConfig(configFile)
	assert.Nil(t, err)

	ConfigVersion = "0.0.0"

	err = LoadConfig(configFile)
	assert.Nil(t, err)

	os.Remove(configFile)
}

func Test_configError(t *testing.T) {
	const configFile = ""

	err := LoadConfig(configFile)
	assert.Error(t, err)
}
