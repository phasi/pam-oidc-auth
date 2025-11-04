# pam-oidc-auth

This is a Open ID Connect module for Linux PAM (Pluggable Authentication Modules). It allows you to configure a so-called "device login" flow for your linux machines that most cloud platforms use, leveraging the [pam_exec.so](https://www.man7.org/linux/man-pages/man8/pam_exec.8.html).

## Get started

To get started you need to either download the distribution package or compile the code into a binary file.

### Get distribution package

#### Option 1: Download from github

This option will be available after the first release.

```bash
wget https://github.com/phasi/pam-oidc-auth/releases/download/v1.0.0/pam_oidc_auth-linux-amd64-v1.0.0.tar.gz
```

#### Option 2: Compile it by yourself

Please note that compiling requires an extra step (installing Golang). It is not covered by the installation instructions.

```bash
git clone https://github.com/phasi/pam-oidc-auth.git
cd pam-oidc-auth
make package-linux
cd dist/packages/
ls
```

Choose the right package (based on architecture) and move it to your home folder for example.

```bash
# using amd64 (x86_64)
mv pam_oidc_auth-linux-amd64-*.tar.gz ~/
cd ~
```

### Extract package

After you have downloaded or compiled the distribution package continue with these steps to extract the package into a better location than your home folder.

```bash
tar vxf pam_oidc_auth*.tar.gz
rm pam_oidc_auth*.tar.gz
sudo mv pam_oidc_auth* /opt/pam_oidc_auth
chown root:root /opt/pam_oidc_auth
cd /opt/pam_oidc_auth
```

After downloading or compiling you should follow the [INSTALLATION.md](INSTALLATION.md "Installations on how to install pam-oidc-auth"). The instructions will assume you have navigated into the correct folder (in this example /opt/pam_oidc_auth).
