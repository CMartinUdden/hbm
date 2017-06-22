package allow

import (
	"fmt"

	"github.com/CMartinUdden/hbm/allow/types"
	"github.com/CMartinUdden/hbm/policy"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/engine-api/types/container"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/juliengk/go-utils/json"
)

var (
	// AllHostPorts Allow all host port publications
	AllHostPorts bool
	// HiHostPorts Allow high host port publications (>1024)
	HiHostPorts bool
)

type volumeOptions struct {
	Recursive bool
	NoSuid    bool
}

// ContainerCreate called from plugin
func ContainerCreate(req authorization.Request, config *types.Config) *types.AllowResult {
	type ContainerCreateConfig struct {
		container.Config
		HostConfig container.HostConfig
	}

	log.Info("Hello from ContainerCreate!")

	cc := &ContainerCreateConfig{}

	err := json.Decode(req.RequestBody, cc)

	if err != nil {
		return &types.AllowResult{Allow: false, Error: err.Error()}
	}

	if err != nil {
		log.Fatal(err)
	}

	if cc.HostConfig.Privileged {
		if !policy.ValidateFlag(config.Username, "container_create_privileged") {
			return &types.AllowResult{Allow: false, Msg: "--privileged param is not allowed"}
		}
	}

	if cc.HostConfig.IpcMode == "host" {
		if !policy.ValidateFlag(config.Username, "container_create_ipc_host") {
			return &types.AllowResult{Allow: false, Msg: "--ipc=\"host\" param is not allowed"}
		}
	}

	if cc.HostConfig.NetworkMode == "host" {
		if !policy.ValidateFlag(config.Username, "container_create_net_host") {
			return &types.AllowResult{Allow: false, Msg: "--net=\"host\" param is not allowed"}
		}
	}

	if cc.HostConfig.PidMode == "host" {
		if !policy.ValidateFlag(config.Username, "container_create_pid_host") {
			return &types.AllowResult{Allow: false, Msg: "--pid=\"host\" param is not allowed"}
		}
	}

	if cc.HostConfig.UsernsMode == "host" {
		if !policy.ValidateFlag(config.Username, "container_create_userns_host") {
			return &types.AllowResult{Allow: false, Msg: "--userns=\"host\" param is not allowed"}
		}
	}

	if cc.HostConfig.UTSMode == "host" {
		if !policy.ValidateFlag(config.Username, "container_create_uts_host") {
			return &types.AllowResult{Allow: false, Msg: "--uts=\"host\" param is not allowed"}
		}
	}

	if len(cc.HostConfig.CapAdd) > 0 {
		for _, c := range cc.HostConfig.CapAdd {
			if !policy.ValidateCap(config.Username, c) {
				return &types.AllowResult{Allow: false, Msg: fmt.Sprintf("Capability %s is not allowed", c)}
			}
		}
	}

	if len(cc.HostConfig.Devices) > 0 {
		for _, dev := range cc.HostConfig.Devices {
			if !policy.ValidateDev(config.Username, dev.PathOnHost) {
				return &types.AllowResult{Allow: false, Msg: fmt.Sprintf("Device %s is not allowed to be exported", dev.PathOnHost)}
			}
		}
	}

	if cc.HostConfig.PublishAllPorts {
		if !policy.ValidateFlag(config.Username, "container_publish_all") {
			return &types.AllowResult{Allow: false, Msg: "--publish-all param is not allowed"}
		}
	}

	if cc.User == "root" {
		if policy.ValidateFlag(config.Username, "container_disallow_root_user") {
			msg := fmt.Sprintf("Running as user %s is not allowed.", cc.User)
			return &types.AllowResult{Allow: false, Msg: msg}
		}
	}

	if len(cc.HostConfig.PortBindings) > 0 {
		for _, pbs := range cc.HostConfig.PortBindings {
			if !policy.ValidateHostPort(config.Username, pbs) {
				return &types.AllowResult{Allow: false, Msg: fmt.Sprintf("Host port publication %s is not allowed", pbs)}
			}
		}
	}

	if len(cc.HostConfig.Binds) > 0 {
		for _, b := range cc.HostConfig.Binds {
			if !policy.ValidateBind(config.Username, b) {
				return &types.AllowResult{Allow: false, Msg: fmt.Sprintf("Volume %s is not allowed to be mounted", b)}
			}
		}
	}

	return &types.AllowResult{Allow: true}
}
