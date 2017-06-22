package plugin

import (
	"fmt"

	"github.com/CMartinUdden/hbm/allow/types"
	"github.com/CMartinUdden/hbm/docker/endpoint"
	"github.com/CMartinUdden/hbm/pkg/uri"
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
func (a *API) Allow(req authorization.Request) *types.AllowResult {

	_, err := uri.GetURIInfo(SupportedVersion, req)
	if err != nil {
		// Log event
		log.Warning(err)

		return &types.AllowResult{Allow: false, Error: err.Error()}
	}

	return &types.AllowResult{Allow: true}
}
