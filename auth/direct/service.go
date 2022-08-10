package direct

import (
	"github.com/pmoieni/go-authn/user"
	"github.com/rs/zerolog"
)

type DirectService struct {
	log zerolog.Logger
	db  user.Queries
}
