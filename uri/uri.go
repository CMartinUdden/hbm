package uri

import (
	"regexp"

	"github.com/CMartinUdden/hbm/allow"
	"github.com/docker/go-plugins-helpers/authorization"
)

// URI structure
type URI struct {
	Method      string
	Re          *regexp.Regexp
	AllowFunc   func(authorization.Request, *allow.Config) *allow.Result
	Action      string
	CmdName     string
	Description string
}

// URIs structure
type URIs []URI

// New function
func New() *URIs {
	return &URIs{}
}

// Register function
func (uris *URIs) Register(method, uri string, af func(authorization.Request, *allow.Config) *allow.Result, action, cmdName, desc string) {
	*uris = append(*uris, URI{Method: method, Re: regexp.MustCompile(uri), AllowFunc: af, Action: action, CmdName: cmdName, Description: desc})
}

// GetURI function
func (uris *URIs) GetURI(method, url string) (URI, error) {
	for _, u := range *uris {
		if u.Method == method {
			if u.Re.MatchString(url) {
				return u, nil
			}
		}
	}

	return URI{}, nil
}

// ActionExists function
func (uris *URIs) ActionExists(action string) bool {
	for _, u := range *uris {
		if u.Action == action {
			return true
		}
	}

	return false
}
