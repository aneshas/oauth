package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func genChallenge() (string, string, error) {
	b, err := randSeq()
	if err != nil {
		return "", "", err
	}

	verifier := strings.ReplaceAll(
		base64.URLEncoding.EncodeToString(b),
		"=", "",
	)

	h := sha256.New()
	h.Write([]byte(verifier))

	challenge := strings.ReplaceAll(
		base64.URLEncoding.EncodeToString(h.Sum(nil)),
		"=", "",
	)

	return verifier, challenge, nil
}

func randSeq() ([]byte, error) {
	b := make([]byte, 64)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
