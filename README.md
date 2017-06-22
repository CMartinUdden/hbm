# HBM (Harbormaster)
Harbormaster is a basic extendable Docker Engine [access authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/) that runs on directly on the host.

By default Harbormaster plugin prevents from executing commands with certains parameters.
 1. Pull images
 2. Start containers
  * `--privileged`
  * `--ipc=host`
  * `--net=host`
  * `--pid=host`
  * `--userns=host`
  * `--uts=host`
  * any Linux capabilities with parameter `--cap-add=[]`
  * any devices added with parameter `--device=[]`
  * any ports added with parameter `--port=`
  * any volumes mounted with parameter `-v`

