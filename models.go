package main

type OIDCProvider struct {
	// OIDC Provider Configuration
	OIDCIssuerURL     string `json:"oidc_issuer_url"`
	OIDCClientID      string `json:"oidc_client_id"`
	OIDCDeviceAuthURL string `json:"oidc_device_auth_url"`
	OIDCTokenURL      string `json:"oidc_token_url"`
	OIDCUserInfoURL   string `json:"oidc_user_info_url"`
}

type Hook struct {
	ScriptPath string   `json:"script_path"`
	Arguments  []string `json:"arguments"`
}

// FormatUserArg replaces "{username}" in Arguments with the actual username
func (h *Hook) FormatUserArg(username string) []string {
	args := make([]string, len(h.Arguments))
	for i, arg := range h.Arguments {
		if arg == "{username}" {
			args[i] = username
		} else {
			args[i] = arg
		}
	}
	return args
}

// System hooks are hooks that interact with the system for user and group management
type SystemHooks struct {
	AddUser                 Hook `json:"add_user"`
	AddUserToSudoGroup      Hook `json:"add_user_to_sudo_group"`
	RemoveUserFromSudoGroup Hook `json:"remove_user_from_sudo_group"`
	GetUserGroups           Hook `json:"get_user_groups"`
}

// Configuration structure
type Config struct {
	OIDCProvider OIDCProvider `json:"oidc_provider"`

	// PAM Configuration
	EnableSSO bool `json:"enable_sso"`
	// List of allowed users
	AllowedUsers []string `json:"allowed_users"`
	// List of required groups for access
	RequiredGroups []string `json:"required_groups"`
	// Name of the group that grants VM admin (sudo) privileges
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
	SudoersFile string `json:"sudoers_file"`

	// PollInterval defines the interval (in seconds) between token polling attempts
	PollInterval int `json:"poll_interval"`
	// Timeout defines the maximum time (in seconds) to wait for user authentication, set to 0 for no timeout.
	// Please note that there are other possible timeouts: (PAM and SSHD) and they need to be configured accordingly.
	Timeout     int         `json:"timeout"`
	SystemHooks SystemHooks `json:"system_hooks"`
}

// Device Authorization Response
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token Response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// User Info Response
type UserInfoResponse struct {
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	Sub               string   `json:"sub"`
}

// Auth Lock File Content
type AuthLock struct {
	User                    string `json:"user"`
	PID                     int    `json:"pid"`
	StartedAt               string `json:"started_at"`
	ExpiresAt               string `json:"expires_at"`
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	PollingID               string `json:"polling_id"`
}

// PAM Environment
type PAMEnv struct {
	User    string
	Service string
	RHost   string
	TTY     string
}
