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
	flags := cmd.Flags()
	flags.BoolVarP(&policy.DebugACL, "debugacl", "a", false, "Debug the ACL subsystem")
	flags.BoolVarP(&policy.AllowWildcard, "allowwildcard", "w", false, "Allow the wildcard user \"*\" to be used for unknown users")
	flags.StringVarP(&policy.Directory, "policydir", "d", "/etc/hbm/policy.d", "ACL policy directory")

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

	serverInitConfig()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	ch := make(chan os.Signal)
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
		log.Fatal(h.ServeUnix("hbm", 0))
	}()

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

	s := <-ch
	log.Infof("Processing signal '%s'", s)
}

var serverDescription = `
Launch the HBM server

`
