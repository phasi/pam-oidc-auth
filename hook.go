package main

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
	AddUser Hook `json:"add_user"`
	// Optional, called after user creation for system integration
	PostUserCreation        Hook `json:"post_user_creation,omitempty"`
	AddUserToSudoGroup      Hook `json:"add_user_to_sudo_group"`
	RemoveUserFromSudoGroup Hook `json:"remove_user_from_sudo_group"`
	GetUserGroups           Hook `json:"get_user_groups"`
}
