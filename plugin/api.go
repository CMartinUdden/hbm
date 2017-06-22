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
