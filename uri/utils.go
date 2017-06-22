package uri

import (
	"fmt"
	"net/url"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/authorization"
)

// Info structure
type Info struct {
	Version string
	Path    string
}

// GetURIInfo function
func GetURIInfo(defaultVersion string, req authorization.Request) (Info, error) {
	reURIWithVersion := regexp.MustCompile(`^/(v[0-9]+\.[0-9]+)(/.*)`)
	reURIWithoutVersion := regexp.MustCompile(`^(/.*)`)

	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		return Info{}, err
	}

	log.Debugf("Authorization request: User: %s, Method: %s, Endpoint: %s", req.User, req.RequestMethod, u.Path)

	result := reURIWithVersion.FindStringSubmatch(u.Path)

	if len(result) == 0 {
		r := reURIWithoutVersion.FindStringSubmatch(u.Path)
		if len(r) > 0 {
			return Info{Version: defaultVersion, Path: r[1]}, nil
		}
	} else {
		return Info{Version: result[1], Path: result[2]}, nil
	}

	return Info{}, fmt.Errorf("%s is not compatible", u.Path)
}
