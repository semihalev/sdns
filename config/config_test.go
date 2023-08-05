package config

import (
	"os"
	"testing"

	"github.com/semihalev/log"
	"github.com/stretchr/testify/assert"
)

func Test_config(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	const configFile = "example.conf"

	err := generateConfig(configFile)
	assert.NoError(t, err)

	_, err = Load(configFile, "0.0.0")
	assert.NoError(t, err)

	os.Remove(configFile)
	os.Remove("db")
}

func Test_configError(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	const configFile = ""

	_, err := Load(configFile, "0.0.0")
	assert.Error(t, err)

	os.Remove("db")
}
