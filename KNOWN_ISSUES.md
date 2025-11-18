# KNOWN ISSUES

## Problem: User is logged out of SSH session after successful login (when logging on to the system for the first time)

When using this authentication module with auto-provisioning turned on, some users experience issues where the first SSH login attempt succeeds but the user is logged out immediately after. On the second attempt user is able to start shell session. This happens only on the first login to a system when a new user is being created.

### Solution: Use Post-User-Creation Hook with your own logic

The PAM OIDC module supports an optional `post_user_creation` hook that runs immediately after user creation. This allows you to perform system-specific integration steps. The actual solution might depend on the system so any scripts to achieve this are not given here because they might not work in your scenario.

#### Configuring the hook

Add the `post_user_creation` hook to your configuration (e.g. below `add_user` hook):

```json
{
  "system_hooks": {
    "add_user": {
      "script_path": "/usr/sbin/useradd",
      "arguments": ["-m", "-s", "/bin/bash", "{username}"]
    },
    "post_user_creation": {
      "script_path": "/path/to/post-user-setup.sh",
      "arguments": ["{username}"]
    }
  }
}
```

Of course if you are happy with the way things are you can totally just skip post_user_creation and continue your day. Just don't be surprised if you have to do 2 logins when logging on a VM for the first time! :) 
