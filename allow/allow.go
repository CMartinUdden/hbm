package allow

import (
	"github.com/docker/go-plugins-helpers/authorization"
)

// Config appconfig structure
type Config struct {
	AppPath  string
	Username string
}

// Result the result structure
type Result struct {
	Allow bool
	Msg   string
	Error string
}

// True always true
func True(req authorization.Request, config *Config) *Result {
	return &Result{Allow: true}
}
