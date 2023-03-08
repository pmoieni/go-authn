package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pmoieni/go-authn/internal/auth"
	"golang.org/x/oauth2"
)

type Service struct {
	AuthHandler     http.HandlerFunc
	CallbackHandler http.HandlerFunc
}

func NewService(
	baseURL,
	issuer,
	issuerURL,
	clientID,
	clientSecret string,
	scopes []string,
) (*Service, error) {
	p := auth.NewProvider(
		baseURL,
		issuer,
		issuerURL,
		clientID,
		clientSecret,
		scopes,
	)

	oidcCfg, err := p.GenOAuthCfg()
	if err != nil {
		return nil, err
	}

	// make authenticator handler
	ah := func(w http.ResponseWriter, r *http.Request) {
		state := auth.RandString(32)
		nonce := auth.RandString(32)

		sc := &http.Cookie{
			Path:     p.BaseURL + "/auth" + p.Issuer,
			Name:     p.Issuer + "_state",
			Value:    state,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().UTC().Add(p.StateExp),
		}

		nc := &http.Cookie{
			Path:     p.BaseURL + "/auth" + p.Issuer,
			Name:     p.Issuer + "_nonce",
			Value:    nonce,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().UTC().Add(p.NonceExp),
		}

		http.SetCookie(w, sc)
		http.SetCookie(w, nc)

		http.Redirect(
			w,
			r,
			oidcCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.AccessTypeOffline),
			http.StatusTemporaryRedirect,
		)
	}

	// make callback handler
	ch := func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie(p.Issuer + "_state")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if r.URL.Query().Get("state") != state.Value {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		oauth2Token, err := oidcCfg.Exchange(context.Background(), r.URL.Query().Get("code"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		idToken, err := p.Verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		nonce, err := r.Cookie(p.Issuer + "_nonce")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if idToken.Nonce != nonce.Value {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	return &Service{ah, ch}, nil
}
