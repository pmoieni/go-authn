package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultStateExp = 10 * time.Minute
	defaultNonceExp = 10 * time.Minute
)

type Issuer string

type Provider struct {
	Issuer       Issuer
	IssuerURL    string
	StateExp     time.Duration
	NonceExp     time.Duration
	ClientID     string
	ClientSecret string
	Scopes       []string
	Verifier     *oidc.IDTokenVerifier
}

func NewProvider(
	issuer,
	issuerURL,
	clientID,
	clientSecret string,
	scopes []string,
) *Provider {
	return &Provider{
		Issuer(issuer),
		issuerURL,
		defaultStateExp,
		defaultNonceExp,
		clientID,
		clientSecret,
		scopes,
		nil,
	}
}

func (p *Provider) getAuthHandler(baseURL string, oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := RandString(32)
		nonce := RandString(32)

		sc := &http.Cookie{
			Path:     baseURL + "/auth" + string(p.Issuer),
			Name:     string(p.Issuer) + "_state",
			Value:    state,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().UTC().Add(p.StateExp),
		}

		nc := &http.Cookie{
			Path:     baseURL + "/auth" + string(p.Issuer),
			Name:     string(p.Issuer) + "_nonce",
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
			oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.AccessTypeOffline),
			http.StatusTemporaryRedirect,
		)
	}
}

func (p *Provider) getCallbackHandler(baseURL string, oauthCfg *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie(string(p.Issuer) + "_state")
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

		oauth2Token, err := oauthCfg.Exchange(context.Background(), r.URL.Query().Get("code"))
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

		nonce, err := r.Cookie(string(p.Issuer) + "_nonce")
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
}

func (p *Provider) genOAuthCfg(baseURL string) (*oauth2.Config, error) {
	op, err := oidc.NewProvider(context.Background(), p.IssuerURL)
	if err != nil {
		return nil, err
	}

	p.Verifier = op.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	})

	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     op.Endpoint(),
		RedirectURL:  baseURL + "/auth/" + string(p.Issuer) + "/callback",
		Scopes:       append([]string{oidc.ScopeOpenID}, p.Scopes...),
	}, nil
}
