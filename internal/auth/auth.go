package auth

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultStateExp = 10 * time.Minute
	defaultNonceExp = 10 * time.Minute
)

type Provider struct {
	BaseURL      string
	Issuer       string
	IssuerURL    string
	StateExp     time.Duration
	NonceExp     time.Duration
	ClientID     string
	ClientSecret string
	Scopes       []string
	Verifier     *oidc.IDTokenVerifier
}

func NewProvider(
	baseURL,
	issuer,
	issuerURL,
	clientID,
	clientSecret string,
	scopes []string,
) *Provider {
	return &Provider{
		baseURL,
		issuer,
		issuerURL,
		defaultStateExp,
		defaultNonceExp,
		clientID,
		clientSecret,
		scopes,
		nil,
	}
}

func (p *Provider) GenOAuthCfg() (*oauth2.Config, error) {
	return p.genOAuthCfg()
}

func (p *Provider) genOAuthCfg() (*oauth2.Config, error) {
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
		RedirectURL:  p.BaseURL + "/auth/" + p.Issuer + "/callback",
		Scopes:       append([]string{oidc.ScopeOpenID}, p.Scopes...),
	}, nil
}
