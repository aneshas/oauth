package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

func loadConfigFor(profile string) (*oauthConfig, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s/%s.json", configDir, profile))
	if err != nil {
		return nil, err
	}

	cfg := oauthConfig{}

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	cfg.init()

	return &cfg, nil
}

type oauthConfig struct {
	AuthorizeURI        string `json:"authorize_uri"`
	TokenURI            string `json:"token_uri"`
	ClientID            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	CodeVerifier        string `json:"-"`
	CodeChallenge       string `json:"-"`
	CodeChallengeMethod string `json:"-"`
	Nonce               string `json:"-"`
	Scope               string `json:"scope"`
	RedirectPath        string `json:"redirect_path"`
	Resource            string `json:"resource"`
	RedirectPort        int    `json:"redirect_port"`
	UseSSL              bool   `json:"use_ssl"`
}

func (cfg *oauthConfig) init() error {
	if cfg.ResponseType == "" {
		cfg.ResponseType = "code"
	}

	if cfg.RedirectPort == 0 {
		cfg.RedirectPort = 8080
	}

	b, err := randSeq()
	if err != nil {
		return err
	}

	cfg.Nonce = string(b)

	if cfg.isImplicit() {
		return nil
	}

	cfg.CodeChallengeMethod = "S256"
	cfg.CodeVerifier, cfg.CodeChallenge, err = genChallenge()
	return err
}

func (cfg *oauthConfig) isImplicit() bool {
	return strings.Contains(cfg.ResponseType, "id_token") ||
		strings.Contains(cfg.ResponseType, "token")
}
