package cmd

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

var serverDescription = `
Launch the HBM server

`

var (
	serverConfig string
)

// NewServerCommand new server command
func NewServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hbm",
		Short: "Launch the HBM server",
		Long:  serverDescription,
		Run:   runStart,
	}
	flags := cmd.Flags()
	flags.BoolVarP(&policy.DebugACL, "debug", "D", false, "Debug the ACL subsystem")
	flags.StringVarP(&policy.Directory, "policydir", "d", "/etc/hbm/policy.d", "ACL policy directory")

	return cmd
}

func serverInitConfig() {
	dockerPluginPath := "/etc/docker/plugins"
	dockerPluginFile := filepath.Join(dockerPluginPath, "hbm.spec")
	pluginSpecContent := []byte("unix://run/docker/plugins/hbm.sock")

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

	if _, err = os.Stat(policy.Directory); err != nil {
		log.Fatal(err)
	}

	log.Info("Server has completed initialization")
}

func runStart(cmd *cobra.Command, args []string) {

	serverInitConfig()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)

	if _, err = os.Stat(policy.Directory); err == nil {
		go func() {
			policy.Init()
			for {
				select {
				case event := <-watcher.Events:
					if (event.Op&fsnotify.Write == fsnotify.Write ||
						event.Op&fsnotify.Remove == fsnotify.Remove) && policy.SupportedFile(event.Name) {
						log.Debugf("Reinit ACL on event: Name: %s, Op: %s", event.Name, event.Op)
						time.Sleep(1000 * time.Millisecond)
						policy.Init()
					}
				case err := <-watcher.Errors:
					log.Error("error:", err)
				}
			}
		}()

		err = watcher.Add(policy.Directory)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	go func() {
		p, err := plugin.NewPlugin()
		if err != nil {
			log.Fatal(err)
		}

		h := authorization.NewHandler(p)

		log.Info("HBM server")

		log.Info("Listening on socket file")
		log.Fatal(h.ServeUnix("hbm", 0))
	}()

	s := <-ch
	log.Infof("Processing signal '%s'", s)
}