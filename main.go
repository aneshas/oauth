package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const localhost = "localhost"

// OauthConfig holds authorization configuration values
type OauthConfig struct {
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

func (cfg OauthConfig) authURI() (string, error) {
	uri, err := url.Parse(cfg.AuthorizeURI)
	if err != nil {
		return "", err
	}

	q := uri.Query()

	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.redirectURI())
	q.Set("response_type", cfg.ResponseType)
	q.Set("resource", cfg.Resource)
	q.Set("scope", cfg.Scope)
	q.Set("state", "abcdefgh123456")
	q.Set("nonce", cfg.Nonce)

	if !cfg.isImplicit() {
		q.Set("code_challenge", cfg.CodeChallenge)
		q.Set("code_challenge_method", cfg.CodeChallengeMethod)
	}

	uri.RawQuery = q.Encode()

	return uri.String(), nil
}

func (cfg OauthConfig) redirectURI() string {
	scheme := "http"

	if cfg.UseSSL {
		scheme = "https"
	}

	uri := fmt.Sprintf("%s://%s:%d%s", scheme, localhost, cfg.RedirectPort, cfg.RedirectPath)

	if cfg.RedirectPort == 80 {
		uri = strings.Replace(uri, ":80", "", 1)
	}

	return uri
}

func (cfg OauthConfig) isImplicit() bool {
	return strings.Contains(cfg.ResponseType, "id_token") ||
		strings.Contains(cfg.ResponseType, "token")
}

func main() {
	// TODO - different profiles (different files in .config - default.json)
	// and add cmd line option -p (profile)
	data, err := ioutil.ReadFile("./okta.json")
	checkFatal(err)

	cfg := OauthConfig{}

	err = json.Unmarshal(data, &cfg)
	checkFatal(err)

	if cfg.ResponseType == "" {
		cfg.ResponseType = "code"
	}

	if cfg.RedirectPort == 0 {
		cfg.RedirectPort = 8080
	}

	if !cfg.isImplicit() {
		cfg.CodeChallengeMethod = "S256"
		cfg.CodeVerifier, cfg.CodeChallenge, err = genChallenge()
		checkFatal(err)
	}

	b, err := randSeq()
	checkFatal(err)
	cfg.Nonce = string(b)

	authURI, err := cfg.authURI()
	checkFatal(err)

	fmt.Printf("Auth URI:\n%s\n", authURI)

	startServer(cfg)
}

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

func startServer(cfg OauthConfig) {
	mux := http.NewServeMux()

	mux.HandleFunc(cfg.RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		handleCode(r, cfg)
		time.AfterFunc(time.Second, func() {
			os.Exit(0)
		})
	})

	if cfg.UseSSL {
		checkFatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", cfg.RedirectPort), "./localhost.crt", "./localhost.key", mux))
	}

	checkFatal(http.ListenAndServe(fmt.Sprintf(":%d", cfg.RedirectPort), mux))
}

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func handleCode(r *http.Request, cfg OauthConfig) {
	code := r.URL.Query().Get("code")

	if code == "" {
		log.Printf("\nno code present in auth response! response url: %s", r.URL)
		log.Println("if you are using implicit flow, check the browser url bar for tokens!")
		return
	}

	form := url.Values{}

	form.Set("code_verifier", cfg.CodeVerifier)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.ClientID)
	form.Set("redirect_uri", cfg.redirectURI())

	resp, err := http.PostForm(cfg.TokenURI, form)
	if err != nil {
		log.Fatalf("error exchanging code for token: %v", err)
	}

	defer resp.Body.Close()

	tokenResp := tokenResponse{}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		log.Fatalf("error decoding token response: %v", err)
	}

	printToken(tokenResp)
}

func printToken(tr tokenResponse) {
	fmt.Printf("\n%s %s\n\n", tr.TokenType, tr.AccessToken)
	fmt.Printf("Expires In: %s\n", time.Duration(tr.ExpiresIn)*time.Second)

	// TODO - Decode and print payload
}
