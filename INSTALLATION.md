# Installation

This is the installation instructions file included in the packaged version of pam-oidc-auth.

## Installation options

### Option 1: Using script

Note! This install script is tested only on Ubuntu 24.04, but it _might_ work on other distributions too. If you're not running Ubuntu it is warmly recommended to check what the install script actually does.

```bash
# Run with sudo permissions
sudo install.sh

# OR as root
sudo su
./install.sh
```

### Option 2: Manual install

Manual installation repeats the steps as seen in _install.sh_.

1. Create a symbolic link to /usr/local/bin

```bash
ln -s $(pwd)/pam_oidc_auth-linux-amd64 /usr/local/bin/pam_oidc_auth
```

2. Configure PAM

Add these lines to "sshd" and "login" under /etc/pam.d/.
They should be placed before the regular auth is included (e.g. on Ubuntu 24.04 the line starts like this: @include common-auth)

```bash
# /etc/pam.d/sshd
auth       sufficient   pam_exec.so quiet expose_authtok stdout /usr/local/bin/pam-oidc
```

```bash
# /etc/pam.d/login
auth       sufficient   pam_exec.so expose_authtok stdout /usr/local/bin/pam-oidc
```

3. Create a config file for SSH Daemon

```bash
echo """
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey keyboard-interactive
LoginGraceTime 120
UsePAM yes
""" | sudo tee /etc/ssh/sshd_config.d/51-pam-oidc-auth.conf
```

4. (Optional) Create SSH Banner

Modify the banner as needed before running the command.

```bash

cat ssh_banner.txt | sudo tee /etc/ssh/ssh_banner.txt
echo "Banner /etc/ssh/ssh_banner.txt" >> /etc/ssh/sshd_config.d/51-pam-oidc-auth.conf
```
