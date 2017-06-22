package server

import (
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CMartinUdden/hbm/plugin"
	"github.com/CMartinUdden/hbm/policy"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
)

var (
	// DebugACL Turn on debug messages for the ACL subsystem
	DebugACL     bool
	serverConfig string
)

// NewServerCommand new server command
func NewServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Launch the HBM server",
		Long:  serverDescription,
		Run:   runStart,
	}

	return cmd
}

func serverInitConfig() {
	dockerPluginPath := "/etc/docker/plugins"
	dockerPluginFile := filepath.Join(dockerPluginPath, "hbm.spec")
	pluginSpecContent := []byte("unix://run/docker/plugins/hbm.sock")

	_, err := exec.LookPath("docker")
	if err != nil {
		log.Fatal("Docker does not seem to be installed. Please check your installation.")

		os.Exit(-1)
	}

	if err := os.MkdirAll(dockerPluginPath, 0755); err != nil {
		log.Fatal(err)
	}

	_, err = os.Stat(dockerPluginFile)
	if err != nil {
		err := ioutil.WriteFile(dockerPluginFile, pluginSpecContent, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Info("Server has completed initialization")
}

func runStart(cmd *cobra.Command, args []string) {

	policyDirectory := "/etc/hbm/policy.d"
	DebugACL = true

	serverInitConfig()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)

	go func() {
		p, err := plugin.NewPlugin()
		if err != nil {
			log.Fatal(err)
		}

		h := authorization.NewHandler(p)

		log.Info("HBM server")

		log.Info("Listening on socket file")
		log.Fatal(h.ServeUnix("root", "hbm"))
	}()

	go func(policyDirectory string, debugACL bool) {
		policy.Init(policyDirectory, debugACL)
		for {
			select {
			case event := <-watcher.Events:
				log.Debugf("event: Name: %s, Op: %s", event.Name, event.Op)
				if event.Op&fsnotify.Write == fsnotify.Write && policy.SupportedFile(event.Name) {
					log.Debugf("Reinit ACL on event: Name: %s, Op: %s", event.Name, event.Op)
					time.Sleep(1000 * time.Millisecond)
					policy.Init(policyDirectory, debugACL)
				}
			case err := <-watcher.Errors:
				log.Error("error:", err)
			}
		}
	}(policyDirectory, DebugACL)

	err = watcher.Add(policyDirectory)
	if err != nil {
		log.Fatal(err)
	}

	s := <-ch
	log.Infof("Processing signal '%s'", s)
}

var serverDescription = `
Launch the HBM server

`
