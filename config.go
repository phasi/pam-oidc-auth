package main

// Configuration structure
type Config struct {
	OIDCProvider Provider `json:"oidc_provider"`

	// You can temporarily disable this module via config (make sure to secure access by other means).
	EnableSSO bool `json:"enable_sso"`
	// List of allowed users
	AllowedUsers []string `json:"allowed_users"`
	// User must be found in ONE of these grouops to gain access (empty = no restriction)
	RequiredGroupsAny []string `json:"required_groups_any"`
	// User must be found in ALL of these groups to gain access (empty = no restriction)
	RequiredGroupsAll []string `json:"required_groups_all"`
	// Name of the group that grants admin (sudo) privileges
	AdminGroupName string `json:"admin_group_name"`
	// System sudo group name (e.g. "sudo" or "wheel")
	SudoGroupName string `json:"sudo_group_name"`
	// Creates a local user account if it does not exist
	CreateLocalUsers bool `json:"create_local_users"`
	// Log file path
	LogFile string `json:"log_file"`
	// Log level: error, warn, info, debug
	LogLevel string `json:"log_level"`
	// Directory for authentication lock files
	LockDir string `json:"lock_dir"`

	// Sudoers file path to configure sudo privileges (file is created if it does not exist)
	// You should not use any existing sudoers file here, but create a separate file (e.g. under /etc/sudoers.d/)
	SudoersFile string `json:"sudoers_file"`

	// PollInterval defines the interval (in seconds) between token polling attempts
	PollInterval int `json:"poll_interval"`
	// Timeout defines the maximum time (in seconds) to wait for user authentication, set to 0 for no timeout.
	// Please note that there are other possible timeouts: (PAM and SSHD) and they need to be configured accordingly.
	Timeout int `json:"timeout"`
	// System hooks configuration
	SystemHooks SystemHooks `json:"system_hooks"`
}

// PAM Environment
type PAMEnv struct {
	User    string
	Service string
	RHost   string
	TTY     string
}
