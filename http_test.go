package server

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type HttpTestSuite struct{}

var _ = Suite(&HttpTestSuite{})

func (s *HttpTestSuite) SetUpTest(c *C) {
	DefaultServer = NewServer()

	CreateTokenHandler(func(token *Token, client interface{}, user interface{}) error {
		switch token.TokenType {
		case AccessToken:
			token.Token = "test_access_token"
			token.Expiration = time.Now().Add(3600 * time.Second)
		case RefreshToken:
			token.Token = "test_refresh_token"
		}
		return nil
	})

	ClientHandler(func(client_id, client_secret string) (client interface{}) {
		if client_id == "123" && (client_secret == "" || client_secret == "s3cr3t") {
			return 123
		}
		return nil
	})
}

func (s *HttpTestSuite) testInvalidRequest(c *C, values url.Values) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "invalid_request")
}

func (s *HttpTestSuite) TestTokenInvalidRequest(c *C) {
	values := make(url.Values)
	s.testInvalidRequest(c, values)

	values.Add("grant_type", "authorization_code")
	s.testInvalidRequest(c, values)

	values.Add("client_id", "123")
	s.testInvalidRequest(c, values)
}

func (s *HttpTestSuite) TestTokenUnsupportedGrantType(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "bogus")
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "unsupported_grant_type")
}

func (s *HttpTestSuite) TestTokenInvalidClientId(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "bogus")
	values.Add("client_id", "invalid")
	values.Add("client_secret", "s3cr3t")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "invalid_client")
}

func (s *HttpTestSuite) TestTokenInvalidClientSecret(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "bogus")
	values.Add("client_id", "123")
	values.Add("client_secret", "invalid")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "invalid_client")
}

func (s *HttpTestSuite) TestTokenPassword(c *C) {
	PasswordGrantHandler(func(username string, password string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "password")
	values.Add("username", "testuser")
	values.Add("password", "testpassword")

	resp, _ := http.PostForm(ts.URL, values)
	c.Assert(resp.StatusCode, Equals, 200)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	token := new(TokenResponse)
	err = json.Unmarshal(body, token)
	c.Assert(err, IsNil)

	c.Assert(token.AccessToken, Equals, "test_access_token")
	c.Assert(token.RefreshToken, Equals, "test_refresh_token")
	c.Assert(token.ExpiresIn, Equals, 3600)
	c.Assert(token.TokenType, Equals, "Bearer")
}

func (s *HttpTestSuite) TestTokenPasswordInvalidRequest(c *C) {
	PasswordGrantHandler(func(username string, password string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "password")
	s.testInvalidRequest(c, values)

	values.Add("username", "asdf")
	s.testInvalidRequest(c, values)
}

func (s *HttpTestSuite) TestTokenPasswordInvalidGrant(c *C) {
	PasswordGrantHandler(func(username string, password string) (user interface{}) {
		return nil
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "password")
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("username", "test_user")
	values.Add("password", "invalid")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "invalid_grant")
}

func (s *HttpTestSuite) TestTokenPasswordUnsupportedGrant(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("grant_type", "password")
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	resp, err := http.PostForm(ts.URL, values)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "unsupported_grant_type")
}

func (s *HttpTestSuite) TestTokenAuthorizationCode(c *C) {
	CodeHandler(func(code, redirect_uri string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "authorization_code")
	values.Add("code", "test_code")
	values.Add("redirect_uri", "http://www.example.com")

	resp, _ := http.PostForm(ts.URL, values)
	c.Assert(resp.StatusCode, Equals, 200)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	token := new(TokenResponse)
	err = json.Unmarshal(body, token)
	c.Assert(err, IsNil)

	c.Assert(token.AccessToken, Equals, "test_access_token")
	c.Assert(token.RefreshToken, Equals, "test_refresh_token")
	c.Assert(token.ExpiresIn, Equals, 3600)
	c.Assert(token.TokenType, Equals, "Bearer")
}

func (s *HttpTestSuite) TestTokenAuthorizationCodeInvalidRequest(c *C) {
	CodeHandler(func(code, redirect_uri string) (user interface{}) {
		return 1
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "authorization_code")
	s.testInvalidRequest(c, values)

	values.Add("code", "asdf")
	s.testInvalidRequest(c, values)
}

func (s *HttpTestSuite) TestTokenAuthorizationCodeAccessDenied(c *C) {
	CodeHandler(func(code, redirect_uri string) (user interface{}) {
		return nil
	})

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("client_id", "123")
	values.Add("client_secret", "s3cr3t")
	values.Add("grant_type", "authorization_code")
	values.Add("code", "test_code")
	values.Add("redirect_uri", "http://www.example.com")

	resp, _ := http.PostForm(ts.URL, values)
	c.Assert(resp.StatusCode, Equals, 400)

	body, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	resp.Body.Close()

	e := Error{}
	err = json.Unmarshal(body, &e)
	c.Assert(err, IsNil)
	c.Assert(e.ErrorName, Equals, "access_denied")
}

func (s *HttpTestSuite) TestAuthValidate(c *C) {
	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "123")
	values.Add("redirect_uri", "http://www.example.com")

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err, IsNil)
}

func (s *HttpTestSuite) TestAuthValidateInvalidRequest(c *C) {
	values := make(url.Values)

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, Equals, "invalid_request")

	values.Add("response_type", "code")
	r.URL.RawQuery = values.Encode()
	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, Equals, "invalid_request")

	values.Add("client_id", "123")
	r.URL.RawQuery = values.Encode()
	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, Equals, "invalid_request")
}

func (s *HttpTestSuite) TestAuthValidateInvalidUri(c *C) {
	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "123")
	values.Add("redirect_uri", "example.com")

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err.(Error).ErrorName, Equals, "invalid_request")
}

func (s *HttpTestSuite) TestAuthValidateOobUrl(c *C) {
	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "123")
	values.Add("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")

	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	c.Assert(err, IsNil)
	r.URL.RawQuery = values.Encode()

	err = AuthValidate(r)
	c.Assert(err, IsNil)
}

func (s *HttpTestSuite) TestAuthSuccess(c *C) {
	ts := httptest.NewServer(http.HandlerFunc(TokenEndpoint))
	defer ts.Close()

	values := make(url.Values)
	values.Add("state", "test_state")
	values.Add("redirect_uri", "http://www.example.com")

	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", ts.URL, nil)
	c.Assert(err, IsNil)

	AuthSuccess(w, r, "asdf")
	c.Assert(w.Code, Equals, 200)
	c.Assert(w.Header.Get("Location"), Equals, "http://www.example.com/")
}
