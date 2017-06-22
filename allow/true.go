package allow

import (
	"github.com/docker/go-plugins-helpers/authorization"
)

// True always true
func True(req authorization.Request, config *Config) *Result {
	return &Result{Allow: true}
}
