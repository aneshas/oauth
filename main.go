package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var configDir string

func init() {
	homeDir, err := os.UserHomeDir()
	checkFatal(err)

	configDir = fmt.Sprintf("%s/.config/oauth", homeDir)
}

func main() {
	profile := flag.String(
		"p",
		"default",
		fmt.Sprintf("name of .json profile file containing oauth2 configuration located in %s", configDir),
	)

	flag.Parse()

	cfg, err := loadConfigFor(*profile)
	checkFatal(err)

	auth := newOauth(cfg)

	checkFatal(auth.start())
}

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
