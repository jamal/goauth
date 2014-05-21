package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	AccessToken  = iota
	RefreshToken = iota
)

type Token struct {
	TokenType  int
	Token      string
	Expiration time.Time
}

func NewAccessToken() *Token {
	return &Token{TokenType: AccessToken}
}

func NewRefreshToken() *Token {
	return &Token{TokenType: RefreshToken}
}

type ClientHandlerFunc func(client_id, client_secret string) (client interface{})

type CodeHandlerFunc func(code, redirect_uri string) (user interface{})

type PasswordGrantHandlerFunc func(username string, password string) (user interface{})

type CreateTokenHandlerFunc func(token *Token, client interface{}, user interface{}) error

type AuthServer struct {
	ClientHandler        ClientHandlerFunc
	CodeHandler          CodeHandlerFunc
	PasswordGrantHandler PasswordGrantHandlerFunc
	CreateTokenHandler   CreateTokenHandlerFunc
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func NewServer() *AuthServer {
	return new(AuthServer)
}

var DefaultServer = NewServer()

func ClientHandler(fn ClientHandlerFunc) {
	DefaultServer.ClientHandler = fn
}

func PasswordGrantHandler(fn PasswordGrantHandlerFunc) {
	DefaultServer.PasswordGrantHandler = fn
}

func CreateTokenHandler(fn CreateTokenHandlerFunc) {
	DefaultServer.CreateTokenHandler = fn
}

func CodeHandler(fn CodeHandlerFunc) {
	DefaultServer.CodeHandler = fn
}

func outputError(w http.ResponseWriter, err Error) {
	w.WriteHeader(err.Code)
	writeResponse(w, err.Json())
}

func output(w http.ResponseWriter, response interface{}) {
	if out, err := json.Marshal(response); err != nil {
		outputError(w, NewServerError(""))
	} else {
		w.WriteHeader(http.StatusOK)
		writeResponse(w, string(out))
	}
}

func writeResponse(w http.ResponseWriter, response string) {
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	w.Header().Add("Cache-Control", "no-store")
	w.Header().Add("Pragma", "no-cache")
	fmt.Fprint(w, response)
}

func AuthValidate(r *http.Request) error {
	response_type := r.FormValue("response_type")
	if response_type == "" {
		return NewInvalidRequestError("Required parameter is missing: response_type")
	}

	client_id := r.FormValue("client_id")
	if client_id == "" {
		return NewInvalidRequestError("Required parameter is missing: client_id")
	}

	redirect_uri := r.FormValue("redirect_uri")
	if redirect_uri != "" {
		// Parse the URL to look for errors (this assumes it is an absolute URL)
		_, err := url.ParseRequestURI(redirect_uri)
		if err != nil {
			return NewInvalidRequestError("Invalid redirect_uri")
		}
	}

	return nil
}

func authRedirect(w http.ResponseWriter, r *http.Request, query url.Values) {
	if state := r.FormValue("state"); state != "" {
		query.Add("state", state)
	}

	redirect_uri := r.FormValue("redirect_uri")
	uri, _ := url.ParseRequestURI(redirect_uri)
	uri.RawQuery = query.Encode()
	http.Redirect(w, r, uri.String(), http.StatusFound)
}

func AuthError(w http.ResponseWriter, r *http.Request, err Error) {
	query := url.Values{}
	query.Add("error", err.ErrorName)
	if err.Description != "" {
		query.Add("error_description", err.Description)
	}
	if err.Uri != "" {
		query.Add("error_uri", err.Uri)
	}
	authRedirect(w, r, query)
}

func AuthSuccess(w http.ResponseWriter, r *http.Request, code string) {
	query := url.Values{}
	query.Add("code", code)
	authRedirect(w, r, query)
}

func (a *AuthServer) createAndOutputTokens(w http.ResponseWriter, client interface{}, user interface{}) {
	access_token := NewAccessToken()
	err := a.CreateTokenHandler(access_token, client, user)
	if err != nil {
		outputError(w, NewServerError(""))
		return
	}

	refresh_token := NewRefreshToken()
	err = a.CreateTokenHandler(refresh_token, client, user)
	if err != nil {
		outputError(w, NewServerError(""))
		return
	}

	response := new(TokenResponse)
	response.AccessToken = access_token.Token
	response.ExpiresIn = int(access_token.Expiration.Sub(time.Now()).Seconds()) + 1
	response.RefreshToken = refresh_token.Token
	response.TokenType = "Bearer"

	output(w, response)
}

func (a *AuthServer) handleAuthorizationCodeTokenRequest(w http.ResponseWriter, r *http.Request, client interface{}) {
	code := r.FormValue("code")
	redirect_uri := r.FormValue("redirect_uri")

	if code == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: code"))
		return
	}
	if redirect_uri == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: redirect_uri"))
		return
	}

	if user := a.CodeHandler(code, redirect_uri); user != nil {
		a.createAndOutputTokens(w, client, user)
		return
	}

	outputError(w, NewAccessDeniedError(""))
	return
}

func (a *AuthServer) handlePasswordTokenRequest(w http.ResponseWriter, r *http.Request, client interface{}) {
	if a.PasswordGrantHandler == nil {
		outputError(w, NewUnsupportedGrantTypeError("'password' grant type is not supported"))
		return
	}

	username := r.FormValue("username")
	if username == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: username"))
		return
	}

	password := r.FormValue("password")
	if password == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: password"))
		return
	}

	if user := a.PasswordGrantHandler(username, password); user != nil {
		a.createAndOutputTokens(w, client, user)
		return
	}

	outputError(w, NewInvalidGrantError(""))
	return
}

func (a *AuthServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// TODO: Also support client auth via Authorization header
	grant_type := r.FormValue("grant_type")
	client_id := r.FormValue("client_id")
	client_secret := r.FormValue("client_secret")

	if grant_type == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: grant_type"))
		return
	}
	if client_id == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: client_id"))
		return
	}
	if client_secret == "" {
		outputError(w, NewInvalidRequestError("Required parameter is missing: client_secret"))
		return
	}

	if client := a.ClientHandler(client_id, client_secret); client != nil {
		switch grant_type {
		case "authorization_code":
			a.handleAuthorizationCodeTokenRequest(w, r, client)
		case "password":
			a.handlePasswordTokenRequest(w, r, client)
		default:
			// TODO: Support custom grant types
			outputError(w, NewUnsupportedGrantTypeError(""))
		}
		return
	}

	outputError(w, NewInvalidClientError(""))
	return
}

func TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	DefaultServer.TokenEndpoint(w, r)
}
