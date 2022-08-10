package goa

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Provider struct {
	Name     string
	StateExp time.Time
	NonceExp time.Time
	ProviderCfg
}

type ProviderCfg struct {
	Issuer       string
	ClientID     string
	ClientSecret string
}

// var (
// 	Google = Provider{
// 		Name:     "google",
// 		Issuer:   "https://accounts.google.com",
// 		StateExp: time.Now().UTC().Add(time.Hour),
// 		NonceExp: time.Now().UTC().Add(time.Hour),
// 	}
// )

var verifier *oidc.IDTokenVerifier

func (c *Config) initProvider(p *Provider) (*oauth2.Config, error) {
	op, err := oidc.NewProvider(context.Background(), p.Issuer)
	if err != nil {
		return &oauth2.Config{}, err
	}

	oidcConfig := &oidc.Config{
		ClientID: p.ClientID,
	}
	verifier = op.Verifier(oidcConfig)

	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     op.Endpoint(),
		RedirectURL:  c.BaseURL + "/auth/" + p.Name + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}
