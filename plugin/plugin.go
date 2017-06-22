package plugin

import (
	"fmt"
	"github.com/CMartinUdden/hbm/allow/types"
	"github.com/CMartinUdden/hbm/pkg/uri"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/authorization"
)

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
	config := types.Config{Username: user}

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
