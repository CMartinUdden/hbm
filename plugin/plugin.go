package plugin

import (
	"fmt"

	"github.com/CMartinUdden/hbm/allow"
	"github.com/CMartinUdden/hbm/endpoint"
	"github.com/CMartinUdden/hbm/uri"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/authorization"
)

// SupportedVersion is the supported Docker API version
var SupportedVersion = "v1.24"

// API structure
type API struct {
	Uris *uri.URIs
}

// Plugin structure
type Plugin struct {
	appPath string
}

// NewPlugin function
func NewPlugin() (*Plugin, error) {
	return &Plugin{appPath: "dummy"}, nil
}

// AuthZReq function
func (p *Plugin) AuthZReq(req authorization.Request) authorization.Response {

	uriinfo, err := uri.GetURIInfo(SupportedVersion, req)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	a, err := NewAPI(uriinfo.Version)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	u, err := a.Uris.GetURI(req.RequestMethod, uriinfo.Path)
	if err != nil {
		msg := fmt.Sprintf("%s is not implemented", uriinfo.Path)

		// Log event
		log.Warning(msg)

		return authorization.Response{Allow: false, Err: msg}
	}

	user := req.User
	config := allow.Config{Username: user}

	r := u.AllowFunc(req, &config)

	if r.Error != "" {
		return authorization.Response{Err: r.Error}
	}

	if !r.Allow {
		return authorization.Response{Msg: r.Msg}
	}

	return authorization.Response{Allow: true}
}

// AuthZRes function
func (p *Plugin) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

// NewAPI function
func NewAPI(version string) (*API, error) {
	if version != SupportedVersion {
		return &API{}, fmt.Errorf("This version of HBM does not support Docker API version %s. Supported version is %s", version, SupportedVersion)
	}

	uris := endpoint.GetUris()

	return &API{Uris: uris}, nil
}

// Allow function
func (a *API) Allow(req authorization.Request) *allow.Result {

	_, err := uri.GetURIInfo(SupportedVersion, req)
	if err != nil {
		// Log event
		log.Warning(err)

		return &allow.Result{Allow: false, Error: err.Error()}
	}

	return &allow.Result{Allow: true}
}
