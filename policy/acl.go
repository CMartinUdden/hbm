package policy

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
)

var theconfig config

var supportedSuffixes = []string{".json"}

type bind struct {
	Path     string
	ReadOnly bool
}

type aclentry struct {
	Name         string
	Members      []string
	Binds        []bind
	Caps         []string
	Devs         []string
	Flags        []string
	Groups       []string
	PortBindings []string
}

type res struct {
	Name   string
	Groups []string
}

type user struct {
	Name   string
	Groups []string
}

type bindgroup struct {
	Name     string
	ReadOnly bool
}

type topbind struct {
	Path   string
	Groups []bindgroup
}

type config struct {
	Groups       []aclentry
	Users        []user
	Binds        []topbind
	Caps         []res
	Devs         []res
	Flags        []res
	PortBindings []res
}

var thegroups map[string]*aclentry
var acl map[string]*aclentry

func calculateacl() {
	thegroups = make(map[string]*aclentry)
	acl = make(map[string]*aclentry)
	var allgroups []string
	var groups []string
	var bg []bindgroup

	// We start by builing the global groups var (thegroups)
	// This contains all the policies group indexed
	for _, g := range theconfig.Groups {
		thegroups[g.Name] = &aclentry{Name: g.Name, Members: g.Members, Binds: g.Binds,
			Caps: g.Caps, Devs: g.Devs, Flags: g.Flags, PortBindings: g.PortBindings}
		allgroups = append(allgroups, g.Name)
	}

	log.Debugf("Groups before group construction %s", allgroups)

	for _, user := range theconfig.Users {
		if len(user.Groups) > 0 && user.Groups[0] == "*" {
			groups = allgroups
		} else {
			groups = user.Groups
		}
		adduser(user, groups)
	}

	for _, bind := range theconfig.Binds {
		if len(bind.Groups) > 0 && bind.Groups[0].Name == "*" {
			for _, b := range allgroups {
				bg = append(bg, bindgroup{Name: b, ReadOnly: bind.Groups[0].ReadOnly})
			}
		} else {
			bg = bind.Groups
		}
		addbind(bind, bg)
	}

	for _, cap := range theconfig.Caps {
		if len(cap.Groups) > 0 && cap.Groups[0] == "*" {
			groups = allgroups
		} else {
			groups = cap.Groups
		}
		addcap(cap.Name, groups, thegroups)
	}

	for _, dev := range theconfig.Devs {
		if len(dev.Groups) > 0 && dev.Groups[0] == "*" {
			groups = allgroups
		} else {
			groups = dev.Groups
		}
		adddev(dev.Name, groups, thegroups)
	}

	for _, flag := range theconfig.Flags {
		if len(flag.Groups) > 0 && flag.Groups[0] == "*" {
			groups = allgroups
		} else {
			groups = flag.Groups
		}
		addflag(flag.Name, groups, thegroups)
	}

	for _, portbinding := range theconfig.PortBindings {
		if len(portbinding.Groups) > 0 && portbinding.Groups[0] == "*" {
			groups = allgroups
		} else {
			groups = portbinding.Groups
		}
		addportbinding(portbinding.Name, groups, thegroups)
	}

	allgroups = []string{}
	for g := range thegroups {
		allgroups = append(allgroups, g)
	}
	log.Debugf("Groups after group construction %s", allgroups)

	// Now we create the ACL var, indexed by user name for easy lookup
	// We treat the users as dummy groups
	for _, g := range thegroups {
		for _, user := range g.Members {
			addgroup(user, g.Name, acl)
			s := []string{user}
			for _, bind := range g.Binds {
				adduserbind(bind, user)
			}
			for _, cap := range g.Caps {
				addcap(cap, s, acl)
			}

			for _, dev := range g.Devs {
				adddev(dev, s, acl)
			}

			for _, flag := range g.Flags {
				addflag(flag, s, acl)
			}

			for _, pb := range g.PortBindings {
				addportbinding(pb, s, acl)
			}
		}
	}
	log.Debugf("Calculated group list: %s", spew.Sdump(thegroups))
	log.Debugf("Calculated ACL: %s", spew.Sdump(acl))
}

// Make sure we have a named entry in a acl map
func addentry(g string, themap map[string]*aclentry) {
	_, ok := themap[g]
	if !ok {
		themap[g] = &aclentry{Name: g}
	}
}

// Add a user to a list of specified groups
func adduser(u user, groups []string) {
	for _, g := range groups {
		addentry(g, thegroups)
		if !stringInSlice(u.Name, thegroups[g].Members) {
			thegroups[g].Members = append(thegroups[g].Members, u.Name)
		}
	}
}

// We want to be able to check for the readonly flag,
// so we have to traverse this struct
func bindExists(b *bind, binds []bind) bool {
	for _, extbind := range binds {
		if b.Path == extbind.Path && b.ReadOnly == extbind.ReadOnly {
			return true
		}
	}
	return false
}

// Adds a bind to the user indexed ACL
func adduserbind(b bind, user string) {
	themap := acl
	addentry(user, themap)
	thebind := &bind{Path: b.Path, ReadOnly: b.ReadOnly}
	if !bindExists(thebind, themap[user].Binds) {
		themap[user].Binds = append(themap[user].Binds, *thebind)
	}
}

// Adds a bind to the group structure using the topbind type
func addbind(b topbind, groups []bindgroup) {
	themap := thegroups
	for _, g := range groups {
		name := g.Name
		path := b.Path
		readonly := g.ReadOnly
		addentry(name, themap)
		thebind := &bind{Path: path, ReadOnly: readonly}
		if !bindExists(thebind, themap[name].Binds) {
			themap[name].Binds = append(themap[name].Binds, *thebind)
		}
	}
}

// Adds a group to the user indexed ACL, for easy lookup
func addgroup(user string, g string, themap map[string]*aclentry) {
	addentry(user, themap)
	if !stringInSlice(g, themap[user].Groups) {
		themap[user].Groups = append(themap[user].Groups, g)
	}
}

// Adds a kernel cap to either the group structure or the user indexed ACL
func addcap(name string, items []string, themap map[string]*aclentry) {
	for _, g := range items {
		addentry(g, themap)
		if !stringInSlice(name, themap[g].Caps) {
			themap[g].Caps = append(themap[g].Caps, name)
		}
	}
}

// Adds a device to either the group structure or the user indexed ACL
func adddev(name string, items []string, themap map[string]*aclentry) {
	for _, g := range items {
		addentry(g, themap)
		if !stringInSlice(name, themap[g].Devs) {
			themap[g].Devs = append(themap[g].Devs, name)
		}
	}
}

// Adds a container create flag to either the group structure or the user indexed ACL
func addflag(name string, items []string, themap map[string]*aclentry) {
	for _, g := range items {
		addentry(g, themap)
		if !stringInSlice(name, themap[g].Flags) {
			themap[g].Flags = append(themap[g].Flags, name)
		}
	}
}

// Adds a host port binding policy to either the group structure or the user indexed ACL
func addportbinding(name string, items []string, themap map[string]*aclentry) {
	for _, g := range items {
		addentry(g, themap)
		if !stringInSlice(name, themap[g].PortBindings) {
			themap[g].PortBindings = append(themap[g].PortBindings, name)
		}
	}
}

func stringInSlice(s string, slice []string) bool {
	for _, i := range slice {
		if i == s {
			return true
		}
	}
	return false
}

// Build the top conf objects
func configmerge(c *config) {

	log.Debugf("in configmerge")
	for _, group := range c.Groups {
		theconfig.Groups = append(theconfig.Groups, group)
	}

	for _, user := range c.Users {
		theconfig.Users = append(theconfig.Users, user)
	}

	for _, bind := range c.Binds {
		theconfig.Binds = append(theconfig.Binds, bind)
	}

	for _, cap := range c.Caps {
		theconfig.Caps = append(theconfig.Caps, cap)
	}

	for _, dev := range c.Devs {
		theconfig.Devs = append(theconfig.Devs, dev)
	}

	for _, flag := range c.Flags {
		theconfig.Flags = append(theconfig.Flags, flag)
	}

	for _, portbinding := range c.PortBindings {
		theconfig.PortBindings = append(theconfig.PortBindings, portbinding)
	}
	log.Debugf("after configmerge")
}

func wf(path string, info os.FileInfo, err error) error {
	var c config
	// .. looking for files that looks like a supported conf file
	if !info.IsDir() && SupportedFile(path) {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Errorf("Unable to read file %s: %s", path, err)
			return err
		}

		c = config{}

		log.Debugf("before unmarshal")
		err = json.Unmarshal(data, &c)

		if err != nil {
			log.Errorf("Unable to parse json file %s: %s", path, err)
			return err
		}
		log.Debugf("after unmarshal")

		// and merge the configuration into the global conf var
		configmerge(&c)

		log.Debugf("Read config: %s", spew.Sdump(theconfig))

	}

	return nil
}
