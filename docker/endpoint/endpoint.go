package endpoint

import (
	"github.com/CMartinUdden/hbm/allow"
	"github.com/CMartinUdden/hbm/pkg/uri"
)

// GetUris register URIs
func GetUris() *uri.URIs {
	uris := uri.New()

	// Common
	uris.Register("GET", `^/containers/json`, allow.True, "container_list", "ps", "List containers")
	uris.Register("POST", `^/containers/create`, allow.ContainerCreate, "container_create", "create", "Create a new container")
	uris.Register("GET", `^/containers/(.+)/json`, allow.True, "container_inspect", "inspect", "Return low-level information on a container or image")
	uris.Register("GET", `^/containers/(.+)/top`, allow.True, "container_top", "top", "Display the running processes of a container")
	uris.Register("GET", `^/containers/(.+)/logs`, allow.True, "container_logs", "logs", "Fetch the logs of a container")
	uris.Register("GET", `^/containers/(.+)/changes`, allow.True, "container_changes", "events", "Get real time events from the server")
	uris.Register("GET", `^/containers/(.+)/export`, allow.True, "container_export", "export", "Export a container's filesystem as a tar archive")
	uris.Register("GET", `^/containers/(.+)/stats`, allow.True, "container_stats", "stats", "Display a live stream of container(s) resource usage statistics")
	uris.Register("POST", `^/containers/(.+)/resize`, allow.True, "container_resize", "resize", "Resize a container TTY")
	uris.Register("POST", `^/containers/(.+)/start`, allow.True, "container_start", "start", "Start one or more stopped containers")
	uris.Register("POST", `^/containers/(.+)/stop`, allow.True, "container_stop", "stop", "Stop a running container")
	uris.Register("POST", `^/containers/(.+)/restart`, allow.True, "container_restart", "restart", "Restart a container")
	uris.Register("POST", `^/containers/(.+)/kill`, allow.True, "container_kill", "kill", "Kill a running container")
	uris.Register("POST", `^/containers/(.+)/update`, allow.True, "container_update", "update", "Update configuration of one or more containers")
	uris.Register("POST", `^/containers/(.+)/rename`, allow.True, "container_rename", "rename", "Rename a container")
	uris.Register("POST", `^/containers/(.+)/pause`, allow.True, "container_pause", "pause", "Pause all processes within a container")
	uris.Register("POST", `^/containers/(.+)/unpause`, allow.True, "container_unpause", "unpause", "Unpause all processes within a container")
	uris.Register("POST", `^/containers/(.+)/attach`, allow.True, "container_attach", "attach", "Attach to a running container")
	uris.Register("GET", `^/containers/(.+)/attach/ws`, allow.True, "container_attach_ws", "attach_ws", "Attach to a running container (websocket)")
	uris.Register("POST", `^/containers/(.+)/wait`, allow.True, "container_wait", "wait", "Block until a container stops, then print its exit code")
	uris.Register("DELETE", `^/containers/(.+)`, allow.True, "container_remove", "rm", "Remove one or more containers")
	uris.Register("POST", `^/containers/(.+)/copy`, allow.True, "container_copy", "cp", "Copy files/folders between a container and the local filesystem")
	uris.Register("HEAD", `^/containers/(.+)/archive`, allow.True, "container_archive_info", "archive", "Retrieving information about files and folders in a container")
	uris.Register("GET", `^/containers/(.+)/archive`, allow.True, "container_archive", "archive", "Get an archive of a filesystem resource in a container")
	uris.Register("PUT", `^/containers/(.+)/archive`, allow.True, "container_archive_extract", "archive", "Extract an archive of files or folders to a directory in a container")
	uris.Register("POST", `^/containers/(.+)/exec`, allow.True, "container_exec_create", "exec", "Run a command in a running container")

	uris.Register("POST", `^/exec/(.+)/start`, allow.True, "exec_start", "exec", "Exec Start")
	uris.Register("POST", `^/exec/(.+)/resize`, allow.True, "exec_resize", "exec", "Exec Resize")
	uris.Register("GET", `^/exec/(.+)/json`, allow.True, "exec_inspect", "exec", "Exec Inspect")

	uris.Register("GET", `^/images/json`, allow.True, "image_list", "images", "List images")
	uris.Register("POST", `^/build`, allow.True, "image_build", "build", "Build an image from a Dockerfile")
	uris.Register("POST", `^/images/create`, allow.True, "image_create", "pull", "Pull an image or a repository from a registry")
	uris.Register("GET", `^/images/(.+)/json`, allow.True, "image_inspect", "inspect", "Return low-level information on a container or image")
	uris.Register("GET", `^/images/(.+)/history`, allow.True, "image_history", "history", "Show the history of an image")
	uris.Register("POST", `^/images/(.+)/push`, allow.True, "image_push", "push", "Push an image or a repository to a registry")
	uris.Register("POST", `^/images/(.+)/tag`, allow.True, "image_tag", "tag", "Tag an image into a repository")
	uris.Register("DELETE", `^/images/(.+)`, allow.True, "image_remove", "rmi", "Remove one or more images")
	uris.Register("GET", `^/images/search`, allow.True, "image_search", "search", "Search the Docker Hub for images")
	uris.Register("GET", `^/images/(.+)/get`, allow.True, "image_save_image", "save", "Save one or more images to a tar archive")
	uris.Register("GET", `^/images/get`, allow.True, "image_save_images", "save", "Save one or more images to a tar archive")
	uris.Register("POST", `^/images/load`, allow.True, "image_load", "load", "Load an image from a tar archive or STDIN")

	uris.Register("OPTIONS", `^/(.*)`, allow.True, "anyroute_options", "", "Anyroute OPTIONS")

	uris.Register("POST", `^/auth`, allow.True, "auth", "login", "Log in to a Docker registry")
	uris.Register("GET", `^/info`, allow.True, "info", "info", "Display system-wide information")
	uris.Register("GET", `^/version`, allow.True, "version", "version", "Show the Docker version information")
	uris.Register("GET", `^/_ping`, allow.True, "ping", "", "Ping the docker server")
	uris.Register("POST", `^/commit`, allow.True, "commit", "commit", "Create a new image from a container's changes")
	uris.Register("GET", `^/events`, allow.True, "events", "events", "Monitor Docker’s events")

	uris.Register("GET", `^/volumes$`, allow.True, "volume_list", "volume ls", "List volumes")
	uris.Register("POST", `^/volumes/create`, allow.True, "volume_create", "volume create", "Create a volume")
	uris.Register("GET", `^/volumes/(.+)`, allow.True, "volume_inspect", "volume inspect", "Return low-level information on a volume")
	uris.Register("DELETE", `^/volumes/(.+)`, allow.True, "volume_remove", "volume rm", "Remove a volume")

	uris.Register("GET", `^/networks$`, allow.True, "network_list", "network ls", "List all networks")
	uris.Register("GET", `^/networks/(.+)`, allow.True, "network_inspect", "network inspect", "Display detailed network information")
	uris.Register("POST", `^/networks/create`, allow.True, "network_create", "network create", "Create a network")
	uris.Register("POST", `^/networks/(.+)/connect`, allow.True, "network_connect", "network connect", "Connect container to a network")
	uris.Register("POST", `^/networks/(.+)/disconnect`, allow.True, "network_disconnect", "network disconnect", "Disconnect container from a network")
	uris.Register("DELETE", `^/networks/(.+)`, allow.True, "network_remove", "network rm", "Remove a network")

	// v1.24
	uris.Register("GET", `^/nodes`, allow.True, "node_list", "node ls", "List nodes")
	uris.Register("GET", `^/nodes/(.+)`, allow.True, "node_inspect", "node inspect", "Return low-level information on the node id")
	uris.Register("DELETE", `^/nodes/(.+)`, allow.True, "node_remove", "node rm", "Remove a node [id] from the swarm")
	uris.Register("POST", `^/nodes/(.+)/update`, allow.True, "node_update", "node update", "Update the node id")

	uris.Register("GET", `^/swarm`, allow.True, "swarm_inspect", "swarm info", "Get swarm info")
	uris.Register("POST", `^/swarm/init`, allow.True, "swarm_init", "swarm init", "Initialize a new swarm")
	uris.Register("POST", `^/swarm/join`, allow.True, "swarm_join", "swarm join", "Join an existing swarm")
	uris.Register("POST", `^/swarm/leave`, allow.True, "swarm_leave", "swarm leave", "Leave a swarm")
	uris.Register("POST", `^/swarm/update`, allow.True, "swarm_update", "swarm update", "Update a swarm")

	uris.Register("GET", `^/services`, allow.True, "service_list", "service ls", "List services")
	uris.Register("POST", `^/services/create`, allow.ServiceCreate, "service_create", "service create", "Create a service")
	uris.Register("DELETE", `^/services/(.+)`, allow.True, "service_remove", "service rm", "Remove a service")
	uris.Register("GET", `^/services/(.+)`, allow.True, "service_inspect", "service inspect", "Return information on the service id")
	uris.Register("POST", `^/services/(.+)/update`, allow.ServiceCreate, "service_update", "service update", "Update a service")

	uris.Register("GET", `^/tasks`, allow.True, "task_list", "stask services", "List tasks")
	uris.Register("GET", `^/tasks/(.+)`, allow.True, "task_inspect", "stask tasks", "Get details on a task")

	return uris
}
