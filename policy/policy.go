package policy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-connections/nat"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	// DebugACL Debug the ACL subsystem
	DebugACL bool
	// Directory the policy directory
	Directory string
	// AllowWildcard allow the wildcard user to be used for unknown users
	AllowWildcard bool
)

// SupportedFile check whether path is a supported configuration file
func SupportedFile(path string) bool {
	ext := filepath.Ext(path)
	return stringInSlice(ext, supportedSuffixes)
}

// Init initializes the policy engine
func Init() error {
	if DebugACL {
		log.SetLevel(log.DebugLevel)
	}

	theconfig = config{}

	if _, err := os.Stat(Directory); err != nil {
		return err
	}

	// Traverse the policy dir ...
	err := filepath.Walk(Directory, wf)
	if err != nil {
		return err
	}

	// When all configuration is merged into the groups structure
	// we calculate the user indexed ACL

	calculateacl()

	return nil
}

// ValidateDev policy
func ValidateDev(u, dev string) bool {
	var ok bool
	if u, ok = getUser(u); !ok {
		return false
	}
	return stringInSlice(dev, acl[u].Devs)
}

// ValidateCap policy
func ValidateCap(u, cap string) bool {
	var ok bool
	if u, ok = getUser(u); !ok {
		return false
	}
	return stringInSlice(cap, acl[u].Caps)
}

// ValidateFlag policy
func ValidateFlag(u, flag string) bool {
	var ok bool
	if u, ok = getUser(u); !ok {
		return false
	}
	return stringInSlice(flag, acl[u].Flags)
}

// ValidateHostPort policy
func ValidateHostPort(u string, flag []nat.PortBinding) bool {
	var ok bool
	if u, ok = getUser(u); !ok {
		return false
	}
	for _, pb := range flag {
		log.Debugf("Loop in ValidateHostPort called, %s, %s, %s", u, pb.HostIP, pb.HostPort)
		for _, policy := range acl[u].PortBindings {
			if matchPortPolicy(pb, policy) {
				return true
			}
		}
	}
	return false
}

// ValidateBind the policy
func ValidateBind(u, flag string) bool {
	var ok bool
	if u, ok = getUser(u); !ok {
		return false
	}
	log.Infof("ValidateBind called, %s, %s", u, flag)
	return matchBind(flag, acl[u].Binds)
}

func getUser(u string) (string, bool) {
	if _, ok := acl[u]; !ok {
		if AllowWildcard {
			return "*", true
		}
		log.Debugf("Unknown user: %s", u)
		return "", false
	}
	return u, true
}

func matchPortPolicy(pb nat.PortBinding, policy string) bool {
	msg := fmt.Sprintf("%s:%s, policy %s", pb.HostIP, pb.HostPort, policy)
	failmsg := fmt.Sprintf("No match for policy: %s", msg)
	passmsg := fmt.Sprintf("Passing port binding: %s", msg)
	errmsg := fmt.Sprintf("Error parsing port binding: %s: error: %%s", msg)

	log.Debugf("matchPortPolicy called %s", msg)
	re, err := regexp.Compile(`^((\d+\.\d+\.\d+\.\d+):)?((\d+)-)?(\d+)$`)
	if err != nil {
		log.Errorf(errmsg, err)
	}
	sl := re.FindStringSubmatch(policy)
	pHiPort, err := strconv.Atoi(sl[5])
	if err != nil {
		log.Errorf(errmsg, err)
	}
	pHostPort, err := strconv.Atoi(pb.HostPort)
	if err != nil {
		log.Errorf(errmsg, err)
	}
	if sl[4] != "" {
		pLowPort, err := strconv.Atoi(sl[4])
		if err != nil {
			log.Errorf(errmsg, err)
		}
		if pLowPort > pHiPort {
			log.Debugf("invalid port range in policy %s", policy)
			log.Debug(failmsg)
			return false
		}
		if pLowPort > pHostPort || pHiPort < pHostPort {
			log.Debugf("port out of range in policy %s", policy)
			log.Debug(failmsg)
			return false
		}
	} else {
		if pHiPort != pHostPort {
			log.Debugf("port mismatch in policy %s", policy)
			log.Debug(failmsg)
			return false
		}
	}
	pIP := sl[2]
	if pIP == "0.0.0.0" || pIP == "" {
		log.Debug(passmsg)
		return true
	}
	if pb.HostIP == "0.0.0.0" || pb.HostIP == "" {
		log.Debug("explicit ip policy")
		log.Debug(failmsg)
		return false
	}
	if pIP != pb.HostIP {
		log.Debug("ip mismatch in explicip ip policy")
		log.Debug(failmsg)
		return false
	}
	log.Debug(passmsg)
	return true
}

func matchBind(bindrequest string, policies []bind) bool {
	failmsg := fmt.Sprintf("No match for bind request: %s", bindrequest)
	log.Debugf("policies %s", policies)
	for _, policy := range policies {
		sl := strings.Split(bindrequest, ":")
		hostpath := sl[0]
		options := sl[2:]
		roreq := stringInSlice("ro", options)
		msg := fmt.Sprintf("request: %s, policy path: %s, policy readonly: %s", bindrequest, policy.Path, policy.ReadOnly)
		passmsg := fmt.Sprintf("Passing host path %s on request: %s", hostpath, msg)
		errmsg := fmt.Sprintf("Error parsing bind request: %s, error: %%s", msg)
		if ok, _ := regexp.MatchString("^/", policy.Path); !ok {
			log.Errorf(errmsg, "Policy path needs to be aboslute")
			continue
		}
		restring := fmt.Sprintf("^(%s|^%s/.*)$", policy.Path, policy.Path)
		re, err := regexp.Compile(restring)
		if err != nil {
			log.Errorf(errmsg, err)
		}

		if re.MatchString(policy.Path) {
			log.Debugf("path match")
			if roreq {
				log.Debugf(passmsg, "readonly")
				return true
			}
			if !policy.ReadOnly {
				log.Debugf(passmsg, "readwrite")
				return true
			}
		}
	}
	log.Debug(failmsg)
	return false
}
