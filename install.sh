#!/bin/bash

INSTALL_DIR="/usr/local/bin"
TARGET_BINARY_NAME="pam_oidc_auth"
SSHD_CONFIG_PATH="/etc/ssh/sshd_config.d/51-pam-oidc-auth.conf"
SSH_BANNER_PATH="/etc/ssh/ssh_banner.txt"
DEFAULT_CONFIG_PATH="/etc/pam-oidc-auth.conf.json"
PAM_D_DIR="/etc/pam.d"

BINARY_NAME="pam_oidc_auth-linux-amd64"


# Since this is only tested on Ubuntu 24, we will limit uninstall script to this OS only
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" != "ubuntu" ] || [ "$VERSION_ID" != "24.04" ]; then
        echo "❌ This install script is only tested on Ubuntu 24.04"
        read -p "🔧 Do you want to proceed anyway? (y|n) " proceed
        if [ "$proceed" != "y" ]; then
            exit 0
        fi
    fi
else
    echo "❌ Cannot determine OS. This install script is only tested on Ubuntu 24.04"
        read -p "🔧 Do you want to proceed anyway? (y|n) " proceed
        if [ "$proceed" != "y" ]; then
            exit 0
        fi
fi


uninstall() {
    echo "=== Uninstalling pam-oidc-auth ==="
    rm -f "${INSTALL_DIR}/${TARGET_BINARY_NAME}"
    cd "${PAM_D_DIR}"
    mv login.bak login
    mv sshd.bak sshd
    cd -
    rm -rf "${SSHD_CONFIG_PATH}"

    if [ -f "${SSH_BANNER_PATH}" ]; then
        rm -f "${SSH_BANNER_PATH}"
    fi

    systemctl reload ssh
    echo "PAM configuration restored from backups."
    echo "✅ Uninstalled pam-oidc-auth successfully."
}


if [[ "$1" == "--uninstall" ]]; then
    uninstall
    exit 0
fi

echo "=== Installing pam_oidc_auth ==="
if [ ! -f "$BINARY_NAME" ]; then
    echo "❌ Binary file '$BINARY_NAME' not found!"
    echo "🔍 Please pass binary file path as argument."
    exit 1
fi
ln -s $(pwd)/"$BINARY_NAME" "${INSTALL_DIR}/${TARGET_BINARY_NAME}"
echo ""
echo "Installed pam_oidc_auth to ${INSTALL_DIR}/${TARGET_BINARY_NAME}"

echo "=== Running post-installation steps ==="

# check if config file exists
if [ -f "${DEFAULT_CONFIG_PATH}" ]; then
    echo "⚠️ Configuration file ${DEFAULT_CONFIG_PATH} already exists."
    read -p "🔧 Do you want to overwrite it with default settings? (y|N) " overwrite

    if [ "$overwrite" == "y" ]; then
        echo "🔧 Overwriting configuration file with default settings."
        # create config file to default location using the binary
        "${INSTALL_DIR}/${TARGET_BINARY_NAME}" create-config
        echo "📝 Configuration file created at ${DEFAULT_CONFIG_PATH}"
    else
        echo "🔧 Keeping existing configuration file."
    fi
else
    # create config file to default location using the binary
    "${INSTALL_DIR}/${TARGET_BINARY_NAME}" create-config
    echo "📝 Configuration file created at ${DEFAULT_CONFIG_PATH}"
fi

# Set proper permissions for the config file
chown root:root "${DEFAULT_CONFIG_PATH}"
# Allow only root to read and write the config file
chmod 600 "${DEFAULT_CONFIG_PATH}"


read -p "🔧 PAY ATTENTION! Before proceeding make sure you have another root session to this server."

echo "=== Backing up PAM configuration files ==="

cd "${PAM_D_DIR}"

mv login login.bak
mv sshd sshd.bak

echo "Backed up original PAM configuration files with .bak extension."

echo " === Installing new PAM configuration files ==="
cd -

cp "pam.d/login" "${PAM_D_DIR}/login"
cp "pam.d/sshd" "${PAM_D_DIR}/sshd"

read -p "🔧 Would you like to use SSH Banner? (y/N) " use_banner

if [ "$use_banner" == "y" ]; then
    cat ssh_banner.txt > "${SSH_BANNER_PATH}"
    echo "Banner ${SSH_BANNER_PATH}" >> "${SSHD_CONFIG_PATH}"
    echo "SSH Banner file created at ${SSH_BANNER_PATH}"
fi

echo """
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthenticationMethods publickey keyboard-interactive
LoginGraceTime 120
UsePAM yes
""" >> ${SSHD_CONFIG_PATH}

echo "PAM configuration updated. Original files backed up with .bak extension."

echo "=== Reloading SSH service ==="
systemctl reload ssh

echo "SSH service reloaded."
echo "✅ Installation completed successfully! 🎉"