package allow

import (
	"github.com/CMartinUdden/hbm/allow/types"
	"github.com/docker/go-plugins-helpers/authorization"
)

// True always true
func True(req authorization.Request, config *types.Config) *types.AllowResult {
	return &types.AllowResult{Allow: true}
}
