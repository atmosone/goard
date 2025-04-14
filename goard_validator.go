package goard

import "context"

type noValidation struct{}

func (v *noValidation) Validate(_ context.Context, login string, password string) bool {
	if login == "" || password == "" {
		return false
	}

	return true
}

func NewDefaultValidator() Validator {
	return &noValidation{}
}
