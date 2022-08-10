package goa

import (
	"net/http"
	"net/mail"
	"unicode"

	"github.com/pmoieni/go-authn/internal/user"
	"github.com/rs/zerolog"
)

var (
	errInvalidEmail = "invalid email"
	errBadPassword  = "password must be at least 8 characters with 1 numeric digit"
)

type AuthService struct {
	log zerolog.Logger
	db  user.Queries
}

func (s *AuthService) validateEmail(e string) error {
	if _, err := mail.ParseAddress(e); err != nil {
		return &errorResponse{Status: http.StatusBadRequest, Message: errInvalidEmail}
	}
	return nil
}

func (s *AuthService) validatePassword(p string) error {
	var (
		hasMinLen = false
		hasNumber = false
	)

	// check if password has minimum length of 8 characters
	if len(p) >= 8 {
		hasMinLen = true
	}
	for _, char := range p {
		if unicode.IsNumber(char) {
			hasNumber = true
		}
	}

	if !hasMinLen || !hasNumber {
		return &errorResponse{Status: http.StatusBadRequest, Message: errBadPassword}
	}

	return nil
}
