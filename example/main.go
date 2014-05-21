package main

import (
	"net/http"

	"github.com/jamal/goauth"
)

// Hard-coding a client and user for this example.
var client = map[string]interface{}{
	"id":                 1,
	"auth_client_id":     "123",
	"auth_client_secret": "s3cr3t",
}

var user = map[string]interface{}{
	"id": 2,
}

func clientHandler(client_id, client_secret string) (client interface{}, ok bool) {
	if client_id == client["client_id"] && (client_secret == "" || client_secret == secret) {
		return client["id"], true
	}

	return nil, false
}

func codeHandler(code, redirect_uri string) (user interface{}, ok bool) {
	if code == "asdf" {

	}
}

func createTokenHandler(token *goauth.Token, user interface{}) error {

}

func authorize(w http.ResponseWriter, r *http.Request) {
	user := getUser()
	if user == nil {
		url := "/login?back=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, url, http.StatusFound)
		return
	}

	// Validates the request parameters and returns the error
	err := goauth.AuthValidate(r)
	if err != nil {
		goauth.AuthError(w, r, err)
	}

	if !isValidScope(scope) {
		goauth.AuthError(w, r, goauth.NewInvalidScopeError())
		return
	}

	client, err := getClient(r.FormValue("client_id"))
	if err != nil {
		goauth.AuthError(w, r, goauth.NewServerError())
		return
	}
	if client == nil {
		goauth.AuthError(w, r, goauth.NewUnauthorizedClientError())
		return
	}

	if r.Method == "POST" {
		if r.FormValue("authorized") == "" {
			// How do we tell the auth server that we failed?
			goauth.AuthError(w, r, goauth.NewAccessDeniedError())
			return
		} else {
			code, err := createCode(client, r.FormValue("redirect_uri"))
			if err != nil {
				goauth.AuthError(w, r, goauth.NewServerError())
				return
			}

			if redirect_uri == "urn:ietf:wg:oauth:2.0:oob" {
				tmpl.ExecuteTemplate(w, "oauth_oob.html", code)
			} else {
				goauth.AuthSuccess(w, r, code)
			}

			return
		}
	}

	tmpl.ExecuteTemplate(w, "oauth_authorize.html", client)
}

func main() {
	goauth.ClientHandlerFunc(clientHandler)
	goauth.CodeHandlerFunc(codeHandler)
	goauth.CreateTokenHandlerFunc(createTokenHandler)

	http.HandleFunc("/oauth2/auth", authorize)
	http.HandleFunc("/oauth2/token", goauth.TokenEndpoint)
}
