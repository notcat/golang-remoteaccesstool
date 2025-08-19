package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

var (
	// encryption key shit
	name, _ = os.Hostname()

	email = "zoey@gmail.com"
)

// ExecuteConfig sets the default config and reads
func ExecuteConfig() {
	name = "serv-" + name

	viper.SetConfigName("canicallyoutonight")
	viper.SetConfigType("toml")
	viper.AddConfigPath("./")
	viper.SetDefault("serverHost", "localhost")
	viper.SetDefault("serverPort", "2526")
	viper.SetDefault("keyPassphrase", "mysupersecurepassword")

	// Create server pgp key for encrypting the output from clients

	// Generate private key String using Curve25519 algorithm
	ecPrivKeyString, err := helper.GenerateKey(name, email, []byte(viper.GetString("keyPassphrase")), "x25519", 0)
	if err != nil {
		fmt.Println(err.Error())
	}

	viper.SetDefault("privateKey", ecPrivKeyString)

	viper.SafeWriteConfig()
}
