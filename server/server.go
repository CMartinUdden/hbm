package server

import (
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
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
	serverConfig    string
	policyDirectory string
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
	policyDirectory := "/etc/hbm/policy.d"
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

	policy.Init(policyDirectory, true)

	log.Info("Server has completed initialization")
}

func runStart(cmd *cobra.Command, args []string) {

	var mutex = &sync.Mutex{}

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

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write && policy.SupportedFile(event.Name) {
					log.Debugf("Reinit ACL on event: Name: %s, Op: %s", event.Name, event.Op)
					time.Sleep(1000 * time.Millisecond)
					mutex.Lock()
					policy.Init("/etc/hbm/policy.d", true)
					mutex.Unlock()
				}
			case err := <-watcher.Errors:
				log.Error("error:", err)
			}
		}
	}()

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
