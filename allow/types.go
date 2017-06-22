package allow

// Config appconfig structure
type Config struct {
	AppPath  string
	Username string
}

// Result the result structure
type Result struct {
	Allow bool
	Msg   string
	Error string
}
