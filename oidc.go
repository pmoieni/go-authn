package goa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Handlers struct {
	AuthHandler     http.HandlerFunc
	CallbackHandler http.HandlerFunc
}

// google oauth config
func (c *Config) NewService(p *Provider) (*Handlers, error) {
	oidcCfg, err := c.initProvider(p)
	if err != nil {
		return &Handlers{}, err
	}

	// make authenticator handler
	authHandler := func(w http.ResponseWriter, r *http.Request) {
		state := randString(32)
		nonce := randString(32)

		sc := &http.Cookie{
			Path:     c.BaseURL + "/auth" + p.Name,
			Name:     p.Name + "_state",
			Value:    state,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  p.StateExp,
		}

		nc := &http.Cookie{
			Path:     c.BaseURL + "/auth" + p.Name,
			Name:     p.Name + "_nonce",
			Value:    nonce,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  p.NonceExp,
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
	callbackHandler := func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie(p.Name + "_state")
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
		idToken, err := verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		nonce, err := r.Cookie(p.Name + "_nonce")
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

	h := Handlers{
		AuthHandler:     authHandler,
		CallbackHandler: callbackHandler,
	}

	return &h, nil
}
