package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const localhost = "localhost"

func newOauth(cfg *oauthConfig) *oauth {
	return &oauth{cfg}
}

type oauth struct {
	cfg *oauthConfig
}

func (o *oauth) start() error {
	err := o.printAuthURI()
	if err != nil {
		return err
	}

	return o.startServer()
}

func (o *oauth) printAuthURI() error {
	authURI, err := o.authURI()
	if err != nil {
		return err
	}

	fmt.Printf("Auth URI:\n%s\n", authURI)

	return nil
}

func (o *oauth) authURI() (string, error) {
	uri, err := url.Parse(o.cfg.AuthorizeURI)
	if err != nil {
		return "", err
	}

	q := uri.Query()

	q.Set("client_id", o.cfg.ClientID)
	q.Set("redirect_uri", o.redirectURI())
	q.Set("response_type", o.cfg.ResponseType)
	q.Set("resource", o.cfg.Resource)
	q.Set("scope", o.cfg.Scope)
	q.Set("state", "abcdefgh123456")
	q.Set("nonce", o.cfg.Nonce)

	if !o.cfg.isImplicit() {
		q.Set("code_challenge", o.cfg.CodeChallenge)
		q.Set("code_challenge_method", o.cfg.CodeChallengeMethod)
	}

	uri.RawQuery = q.Encode()

	return uri.String(), nil
}

func (o *oauth) startServer() error {
	mux := http.NewServeMux()

	mux.HandleFunc(o.cfg.RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		o.handleResponse(r)

		fmt.Fprintf(w, `<script>window.close();</script>`)

		time.AfterFunc(time.Second, func() {
			os.Exit(0)
		})
	})

	addr := fmt.Sprintf(":%d", o.cfg.RedirectPort)

	if o.cfg.UseSSL {
		certPath := fmt.Sprintf("%s/localhost.crt", configDir)
		keyPath := fmt.Sprintf("%s/localhost.key", configDir)

		return http.ListenAndServeTLS(
			addr,
			certPath,
			keyPath,
			mux,
		)
	}

	return http.ListenAndServe(addr, mux)
}

func (o *oauth) handleResponse(r *http.Request) {
	code := r.URL.Query().Get("code")

	if code == "" {
		log.Printf("\nno code present in auth response! response url: %s\n", r.URL)
		log.Println("implicit flow is not supported atm!")
		return
	}

	tr := o.getTokenFrom(code)
	o.printToken(tr)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (o *oauth) printToken(tr tokenResponse) {
	fmt.Printf("\n%s %s\n\n", tr.TokenType, tr.AccessToken)
	fmt.Printf("Expires In: %s\n", time.Duration(tr.ExpiresIn)*time.Second)

	fmt.Println("\nClaims:")

	parts := strings.Split(tr.AccessToken, ".")
	claimBytes, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(parts[1])
	if err != nil {
		log.Fatalf("error decoding claims: %v", err)
	}

	var buff bytes.Buffer

	err = json.Indent(&buff, claimBytes, "", "  ")
	if err != nil {
		log.Fatalf("error decoding claims: %v", err)
	}

	fmt.Println(buff.String())
}

func (o *oauth) getTokenFrom(code string) tokenResponse {
	form := url.Values{}

	form.Set("code_verifier", o.cfg.CodeVerifier)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", o.cfg.ClientID)
	form.Set("redirect_uri", o.redirectURI())

	resp, err := http.PostForm(o.cfg.TokenURI, form)
	if err != nil {
		log.Fatalf("error exchanging code for token: %v", err)
	}

	defer resp.Body.Close()

	tokenResp := tokenResponse{}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		log.Fatalf("error decoding token response: %v", err)
	}

	return tokenResp
}

func (o *oauth) redirectURI() string {
	scheme := "http"

	if o.cfg.UseSSL {
		scheme = "https"
	}

	uri := fmt.Sprintf("%s://%s:%d%s", scheme, localhost, o.cfg.RedirectPort, o.cfg.RedirectPath)

	if o.cfg.RedirectPort == 80 {
		uri = strings.Replace(uri, ":80", "", 1)
	}

	return uri
}
