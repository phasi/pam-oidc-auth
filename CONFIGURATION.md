# PAM OIDC Authentication Configuration

This document describes all configuration options for the PAM OIDC authentication module. The module authenticates users against an OpenID Connect (OIDC) provider using the device flow and can optionally create local user accounts and manage sudo privileges.

## Table of Contents

1. [Configuration File Location](#configuration-file-location)
2. [OIDC Provider Configuration](#oidc-provider-configuration)
3. [Authentication and Access Control](#authentication-and-access-control)
4. [User Management](#user-management)
5. [System Integration](#system-integration)
6. [Logging and Debugging](#logging-and-debugging)
7. [System Hooks](#system-hooks)
8. [Claim Mapping](#claim-mapping)
9. [Discovery vs Manual Configuration](#discovery-vs-manual-configuration)
10. [Complete Configuration Examples](#complete-configuration-examples)

## Configuration File Location

The module looks for configuration in the following order:

1. Command line parameter: `-config /path/to/config.json`
2. Environment variable: `PAM_OIDC_AUTH_CONFIG`
3. Default location: `/etc/pam-oidc-auth.conf.json`

## OIDC Provider Configuration

### Basic Provider Settings

```json
{
  "oidc_provider": {
    "oidc_client_id": "your-client-id",
    "oidc_issuer_url": "https://provider.com/realm",
    "oidc_device_auth_url": "https://provider.com/auth/device",
    "oidc_token_url": "https://provider.com/token",
    "oidc_user_info_url": "https://provider.com/userinfo",
    "jwks_uri": "https://provider.com/.well-known/jwks.json"
  }
}
```

#### Required Fields

- **`oidc_client_id`** (string): Client ID from your OIDC provider
- **`oidc_issuer_url`** (string): Issuer URL for token validation

#### Manual Endpoint Configuration

- **`oidc_device_auth_url`** (string): Device authorization endpoint
- **`oidc_token_url`** (string): Token endpoint
- **`oidc_user_info_url`** (string): UserInfo endpoint
- **`jwks_uri`** (string): JSON Web Key Set URI for token validation

### Automatic Discovery

Instead of manually specifying endpoints, you can use OIDC discovery:

```json
{
  "oidc_provider": {
    "use_discovery": true,
    "auto_discovery_url": "https://provider.com/.well-known/openid_configuration",
    "oidc_client_id": "your-client-id"
  }
}
```

#### Discovery Options

- **`use_discovery`** (boolean): Enable automatic endpoint discovery
- **`auto_discovery_url`** (string): OIDC discovery document URL

**Note**: Manual endpoint configuration takes precedence over discovery. You can use discovery while overriding specific endpoints.

## Authentication and Access Control

### Basic Access Control

Note that if you temporarily disable authentication by setting `enable_sso` to false you will need another way to access the system, like SSH keys. You should always have a another shell session to the server when making configurations to avoid being blocked.

```json
{
  "enable_sso": true,
  "allowed_users": ["user1@company.com", "user2@company.com"],
  "required_groups": ["employees", "contractors"],
  "timeout": 300,
  "poll_interval": 5
}
```

#### Access Control Options

- **`enable_sso`** (boolean): Globally enable/disable the module
- **`allowed_users`** (array): List of allowed usernames. Empty array allows all users
- **`required_groups`** (array): List of required group memberships. Empty array requires no groups
- **`timeout`** (integer): Authentication timeout in seconds (0 = no timeout, or use timeout from OIDC provider)
- **`poll_interval`** (integer): Token polling interval in seconds

## User Management

### Local User Creation

`admin_group_name`is checked from user groups (in the JWT token). It defines which group from the auth provider to map to superuser group on the system.

```json
{
  "create_local_users": true,
  "admin_group_name": "administrators",
  "sudo_group_name": "sudo",
  "sudoers_file": "/etc/sudoers.d/pam-oidc-users"
}
```

#### User Management Options

- **`create_local_users`** (boolean): Automatically create local user accounts if they don't exist
- **`admin_group_name`** (string): OIDC group that grants admin privileges
- **`sudo_group_name`** (string): Local system sudo group name ("sudo" or "wheel")
- **`sudoers_file`** (string): Path to sudoers file for managing admin privileges

**Important**: Use a dedicated sudoers file (e.g., under `/etc/sudoers.d/`) rather than modifying any existing files.

## System Integration

### Lock File Management

```json
{
  "lock_dir": "/tmp/pam-oidc-locks"
}
```

- **`lock_dir`** (string): Temporary directory for authentication session lock files

The module uses lock files to:

- Prevent concurrent authentication attempts by the same user
- Share device codes between multiple repeated login attempts

Lock file is deleted after login (either successful or failed).

## Logging and Debugging

```json
{
  "log_file": "/var/log/pam-oidc-auth.log",
  "log_level": "info"
}
```

### Logging Options

- **`log_file`** (string): Log file path (empty = stderr)
- **`log_level`** (string): Log level (`error`, `warn`, `info`, `debug`)

Avoid using debug logging when in production or production-like conditions. (Tokens are logged in debug mode!)

When setting things up however you might need to see a bit more information.

### Log Levels

- **`error`**: Only errors and critical issues
- **`warn`**: Warnings and errors
- **`info`**: General information, warnings, and errors
- **`debug`**: Detailed debugging information (includes tokens and claims)

## System Hooks

System hooks allow you to customize user and group management operations to match your system.

```json
{
  "system_hooks": {
    "add_user": {
      "script_path": "/usr/sbin/useradd",
      "arguments": ["-m", "-s", "/bin/bash", "{username}"]
    },
    "post_user_creation": {
      "script_path": "",
      "arguments": ["{username}"]
    },
    "add_user_to_sudo_group": {
      "script_path": "/usr/sbin/usermod",
      "arguments": ["-aG", "sudo", "{username}"]
    },
    "remove_user_from_sudo_group": {
      "script_path": "/usr/sbin/gpasswd",
      "arguments": ["-d", "{username}", "sudo"]
    },
    "get_user_groups": {
      "script_path": "/usr/bin/groups",
      "arguments": ["{username}"]
    }
  }
}
```

### Available Hooks

- **`add_user`**: Create a new local user account
- **`post_user_creation`**: Run after user creation (optional, for system integration)
- **`add_user_to_sudo_group`**: Add user to sudo group
- **`remove_user_from_sudo_group`**: Remove user from sudo group
- **`get_user_groups`**: Get user's group memberships

When using `post_user_creation` please remember that the authentication is not completed before this module returns 0 to pam_exec.so. This means you shouldn't run your custom logic for too long (and keep your users waiting).

The script can be used for notifications etc.

### Hook Format

Each hook consists of:

- **`script_path`**: Path to the executable/script
- **`arguments`**: Array of arguments, where `{username}` is replaced with the actual username

## Claim Mapping

Claim mapping defines how to extract user information from OIDC tokens:

```json
{
  "oidc_provider": {
    "claim_map": {
      "username": {
        "claim_name": "preferred_username",
        "token_source": "access_token"
      },
      "groups": {
        "claim_name": "groups",
        "token_source": "id_token"
      },
      "email": {
        "claim_name": "email",
        "token_source": "auto"
      },
      "subject": {
        "claim_name": "sub",
        "token_source": "auto"
      },
      "fallback_to_userinfo": false
    }
  }
}
```

### Claim Sources

- **`claim_name`**: Name of the claim in the token/response
- **`token_source`**: Where to find the claim

#### Token Source Options

- **`id_token`**: Extract from ID token (JWT validated)
- **`access_token`**: Extract from access token (no validation)
- **`userinfo`**: Extract from UserInfo endpoint
- **`auto`**: Try ID token, then access token, then UserInfo (if enabled)

#### Fallback Behavior

- **`fallback_to_userinfo`**: If true, fall back to UserInfo endpoint when claims are missing from tokens. _This is a desperate method and usually will not work_.

### Provider-Specific Claim Patterns

#### Keycloak

```json
"claim_map": {
  "username": {"claim_name": "preferred_username", "token_source": "access_token"},
  "groups": {"claim_name": "groups", "token_source": "access_token"}
}
```

#### Azure AD

```json
"claim_map": {
  "username": {"claim_name": "upn", "token_source": "access_token"},
  "groups": {"claim_name": "groups", "token_source": "id_token"}
}
```

## Discovery vs Manual Configuration

### Pure Discovery Configuration

Use only discovery with no manual endpoints:

```json
{
  "oidc_provider": {
    "use_discovery": true,
    "auto_discovery_url": "https://provider.com/.well-known/openid_configuration",
    "oidc_client_id": "client-id",
    "claim_map": {...}
  }
}
```

### Hybrid Configuration

Use discovery but override specific endpoints:

```json
{
  "oidc_provider": {
    "use_discovery": true,
    "auto_discovery_url": "https://provider.com/.well-known/openid_configuration",
    "oidc_device_auth_url": "https://custom.provider.com/device_auth",
    "oidc_client_id": "client-id",
    "claim_map": {...}
  }
}
```

### Manual Configuration

Specify all endpoints manually:

```json
{
  "oidc_provider": {
    "oidc_issuer_url": "https://provider.com",
    "oidc_device_auth_url": "https://provider.com/device_auth",
    "oidc_token_url": "https://provider.com/token",
    "oidc_user_info_url": "https://provider.com/userinfo",
    "jwks_uri": "https://provider.com/jwks",
    "oidc_client_id": "client-id",
    "claim_map": {...}
  }
}
```

## Complete Configuration Examples

### Keycloak with Discovery

```json
{
  "oidc_provider": {
    "use_discovery": true,
    "auto_discovery_url": "https://keycloak.company.com/realms/company/.well-known/openid_configuration",
    "oidc_client_id": "ssh-access",
    "claim_map": {
      "username": {
        "claim_name": "preferred_username",
        "token_source": "access_token"
      },
      "groups": { "claim_name": "groups", "token_source": "access_token" },
      "email": { "claim_name": "email", "token_source": "access_token" },
      "subject": { "claim_name": "sub", "token_source": "access_token" },
      "fallback_to_userinfo": false
    }
  },
  "enable_sso": true,
  "create_local_users": true,
  "admin_group_name": "administrators",
  "sudo_group_name": "sudo",
  "sudoers_file": "/etc/sudoers.d/pam-oidc-users",
  "required_groups": ["employees"],
  "timeout": 300,
  "poll_interval": 5,
  "lock_dir": "/tmp/pam-oidc-locks",
  "log_level": "info",
  "system_hooks": {
    "add_user": {
      "script_path": "/usr/sbin/useradd",
      "arguments": ["-m", "-s", "/bin/bash", "{username}"]
    },
    "post_user_creation": {
      "script_path": "/usr/local/bin/post-user-setup.sh",
      "arguments": ["{username}"]
    },
    "add_user_to_sudo_group": {
      "script_path": "/usr/sbin/usermod",
      "arguments": ["-aG", "sudo", "{username}"]
    },
    "remove_user_from_sudo_group": {
      "script_path": "/usr/sbin/gpasswd",
      "arguments": ["-d", "{username}", "sudo"]
    },
    "get_user_groups": {
      "script_path": "/usr/bin/groups",
      "arguments": ["{username}"]
    }
  }
}
```

### Azure AD Manual Configuration

```json
{
  "oidc_provider": {
    "oidc_issuer_url": "https://login.microsoftonline.com/tenant-id/v2.0",
    "oidc_client_id": "application-id",
    "oidc_device_auth_url": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/devicecode",
    "oidc_token_url": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
    "oidc_user_info_url": "https://graph.microsoft.com/oidc/userinfo",
    "jwks_uri": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
    "claim_map": {
      "username": {
        "claim_name": "upn",
        "token_source": "access_token"
      },
      "groups": { "claim_name": "groups", "token_source": "id_token" },
      "email": { "claim_name": "email", "token_source": "access_token" },
      "subject": { "claim_name": "sub", "token_source": "access_token" },
      "fallback_to_userinfo": false
    }
  },
  "enable_sso": true,
  "create_local_users": true,
  "admin_group_name": "<id>",
  "sudo_group_name": "sudo",
  "required_groups": [],
  "timeout": 300,
  "poll_interval": 5,
  "log_level": "info"
}
```

### Minimal Configuration

```json
{
  "oidc_provider": {
    "use_discovery": true,
    "auto_discovery_url": "https://provider.com/.well-known/openid_configuration",
    "oidc_client_id": "client-id",
    "claim_map": {
      "username": {
        "claim_name": "preferred_username",
        "token_source": "auto"
      },
      "groups": { "claim_name": "groups", "token_source": "auto" }
    }
  },
  "enable_sso": true,
  "create_local_users": false,
  "log_level": "info"
}
```

## Usage

### Command Line Options

```bash
# Use default config location
./pam-oidc-auth

# Specify config file
./pam-oidc-auth -config /path/to/config.json

# Test mode (interactive)
./pam-oidc-auth test -config /path/to/config.json

# Show version
./pam-oidc-auth version
```

### Environment Variables

- **`PAM_OIDC_AUTH_CONFIG`**: Path to configuration file (overrides default location)

### Testing Configuration

Use test mode at your server to validate your configuration:

```bash
./pam-oidc-auth test -config your-config.json
```

This will prompt for a username and walk through the authentication flow without requiring PAM integration.

## Security Considerations

1. **Protect the configuration file**: Contains sensitive client credentials
2. **Use dedicated sudoers file**: Don't modify the main `/etc/sudoers` file
3. **Log level in production**: Use `info` or `warn` level to avoid logging sensitive data
4. **JWKS validation**: Always use JWKS URI or discovery for token validation
5. **Group-based access**: Use `required_groups` to limit access to authorized users
6. **Timeout configuration**: Set appropriate timeouts to balance security and usability
