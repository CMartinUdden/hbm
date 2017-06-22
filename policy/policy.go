package policy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-connections/nat"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SupportedFile check whether path is a supported configuration file
func SupportedFile(path string) bool {
	ext := filepath.Ext(path)
	return stringInSlice(ext, supportedSuffixes)
}

// Init initializes the policy engine
func Init(policydir string, debug bool) error {
	if debug {
		log.SetLevel(log.DebugLevel)
	}

	theconfig = config{}

	// Traverse the policy dir ...
	err := filepath.Walk(policydir, wf)
	if err != nil {
		return err
	}

	// When all configuration is merged into the groups structure
	// we calculate the user indexed ACL

	calculateacl()

	return nil
}

// ValidateDev policy
func ValidateDev(user, dev string) bool {
	if !userExist(user) {
		return false
	}
	return stringInSlice(dev, acl[user].Flags)
}

// ValidateCap policy
func ValidateCap(user, cap string) bool {
	if !userExist(user) {
		return false
	}
	return stringInSlice(cap, acl[user].Flags)
}

// ValidateFlag policy
func ValidateFlag(user, flag string) bool {
	if !userExist(user) {
		return false
	}
	return stringInSlice(flag, acl[user].Flags)
}

// ValidateHostPort policy
func ValidateHostPort(user string, flag []nat.PortBinding) bool {
	if !userExist(user) {
		return false
	}
	for _, pb := range flag {
		log.Debugf("Loop in ValidateHostPort called, %s, %s, %s", user, pb.HostIP, pb.HostPort)
		for _, policy := range acl[user].PortBindings {
			if matchPortPolicy(pb, policy) {
				return true
			}
		}
	}
	return false
}

// ValidateBind the policy
func ValidateBind(user, flag string) bool {
	if !userExist(user) {
		return false
	}
	log.Infof("ValidateBind called, %s, %s", user, flag)
	return matchBind(flag, acl[user].Binds)
}

func userExist(user string) bool {
	if _, ok := acl[user]; !ok {
		log.Debugf("Unknown user: %s", user)
		return false
	}
	return true
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
