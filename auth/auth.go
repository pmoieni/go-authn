package auth

import (
	"net/http"
)

const (
	ScopeProfile = "profile"
	ScopeEmail   = "email"
)

type Service struct {
	AuthHandler     http.HandlerFunc
	CallbackHandler http.HandlerFunc
}

func NewService(baseURL string, ps []*Provider) (map[Issuer]*Service, error) {
	ss := map[Issuer]*Service{}

	for _, p := range ps {
		oauthCfg, err := p.genOAuthCfg(baseURL)
		if err != nil {
			return nil, err
		}

		ss[p.Issuer] = &Service{
			p.getAuthHandler(baseURL, oauthCfg),
			p.getCallbackHandler(baseURL, oauthCfg),
		}
	}

	return ss, nil
}
