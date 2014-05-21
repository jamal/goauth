package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Error struct {
	Code        int    `json:"-"`
	ErrorName   string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Uri         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	ret := fmt.Sprintf("error=%s", e.ErrorName)
	if e.Description != "" {
		ret = ret + fmt.Sprintf("&error_description=%s", e.Description)
	}
	if e.Uri != "" {
		ret = ret + fmt.Sprintf("&error_uri=%s", e.Uri)
	}

	return ret
}

func (e Error) Json() string {
	if body, _ := json.Marshal(e); body != nil {
		return string(body)
	}
	return "{}"
}

func NewInvalidRequestError(description string) Error {
	return Error{http.StatusBadRequest, "invalid_request", description, ""}
}

func NewInvalidClientError(description string) Error {
	return Error{http.StatusBadRequest, "invalid_client", description, ""}
}

func NewUnauthorizedClientError(description string) Error {
	return Error{http.StatusBadRequest, "unauthorized_client", description, ""}
}

func NewAccessDeniedError(description string) Error {
	return Error{http.StatusBadRequest, "access_denied", description, ""}
}

func NewUnsupportedResponseTypeError(description string) Error {
	return Error{http.StatusBadRequest, "unsupported_response_type", description, ""}
}

func NewInvalidScopeError(description string) Error {
	return Error{http.StatusBadRequest, "invalid_scope", description, ""}
}

func NewServerError(description string) Error {
	return Error{http.StatusInternalServerError, "server_error", description, ""}
}

func NewTemporarilyUnavailableError(description string) Error {
	return Error{http.StatusServiceUnavailable, "temporarily_unavailable", description, ""}
}

func NewInvalidGrantError(description string) Error {
	return Error{http.StatusBadRequest, "invalid_grant", description, ""}
}

func NewUnsupportedGrantTypeError(description string) Error {
	return Error{http.StatusBadRequest, "unsupported_grant_type", description, ""}
}
