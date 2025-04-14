package goard

import (
	"encoding/json"
	"net/http"
)

type jsonTranport struct{}

func (t *jsonTranport) SignIn(r *http.Request) (login, password string, err error) {
	if r.Method != http.MethodPost {
		return "", "", ErrMethod
	}
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", "", err
	}
	return req.Login, req.Password, nil
}

func (t *jsonTranport) SignUp(r *http.Request) (account json.RawMessage, login, password string, err error) {
	if r.Method != http.MethodPost {
		return nil, "", "", ErrMethod
	}
	var req struct {
		Account  json.RawMessage `json:"account"`
		Login    string          `json:"login"`
		Password string          `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, "", "", err
	}
	return req.Account, req.Login, req.Password, nil
}

func (t *jsonTranport) SetRole(r *http.Request) (account int64, role string, err error) {
	if r.Method != http.MethodPatch {
		return 0, "", ErrMethod
	}
	var req struct {
		Account int64  `json:"account"`
		Role    string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return 0, "", err
	}
	return req.Account, req.Role, nil
}

func (t *jsonTranport) UnsetRole(r *http.Request) (account int64, role string, err error) {
	if r.Method != http.MethodPatch {
		return 0, "", ErrMethod
	}
	var req struct {
		Account int64  `json:"account"`
		Role    string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return 0, "", err
	}
	return req.Account, req.Role, nil
}

func NewJSONTransport() Transport {
	return &jsonTranport{}
}
