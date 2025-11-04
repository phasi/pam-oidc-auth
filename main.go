package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Logger levels
const (
	LogLevelError = 1
	LogLevelWarn  = 2
	LogLevelInfo  = 3
	LogLevelDebug = 4
)

var (
	defaultConfigFilePath = "/etc/pam-oidc-auth.conf.json"
	configFilePath        string
	config                *Config
	pamEnv                *PAMEnv
	logLevel              int
	logFile               *os.File
	httpClient            *http.Client
	testMode              bool = false
	showVersion           bool = false
)

func init() {
	// Initialize HTTP client with timeout
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
}
func createDefaultConfig(path string) error {

	defaultConfig := Config{
		OIDCProvider: Provider{
			OIDCIssuerURL:     "https://example.com",
			ClientID:          "your-client-id",
			OIDCDeviceAuthURL: "https://example.com/device_authorization",
			OIDCTokenURL:      "https://example.com/token",
			OIDCUserInfoURL:   "https://example.com/userinfo",
			ClaimMap: ClaimMap{
				Username: ClaimSource{
					ClaimName:   "preferred_username",
					TokenSource: TokenSourceAuto,
				},
				Groups: ClaimSource{
					ClaimName:   "groups",
					TokenSource: TokenSourceAuto,
				},
				Email: ClaimSource{
					ClaimName:   "email",
					TokenSource: TokenSourceAuto,
				},
				Subject: ClaimSource{
					ClaimName:   "sub",
					TokenSource: TokenSourceAuto,
				},
				FallbackToUserInfo: false,
			},
			// UseDiscovery: false,
			JWKSUri: "https://example.com/.well-known/jwks.json",
		},
		EnableSSO:         true,
		AllowedUsers:      []string{},
		RequiredGroupsAny: []string{},
		RequiredGroupsAll: []string{},
		CreateLocalUsers:  true,
		LogFile:           "/var/log/pam-oidc.log",
		LogLevel:          "info",
		LockDir:           "/tmp/pam-oidc-locks",
		SudoersFile:       "/etc/sudoers.d/90-pam-oidc-auth",
		PollInterval:      5,
		Timeout:           0,
		SystemHooks: SystemHooks{
			AddUser: Hook{
				ScriptPath: "/usr/sbin/useradd",
				Arguments:  []string{"-m", "-s", "/bin/bash", "{username}"},
			},
			// PostUserCreation: Hook{
			//     ScriptPath: "/usr/local/bin/post-user-setup.sh",
			//     Arguments:  []string{"{username}"},
			// },
			AddUserToSudoGroup: Hook{
				ScriptPath: "/usr/sbin/usermod",
				Arguments:  []string{"-aG", "sudo", "{username}"},
			},
			RemoveUserFromSudoGroup: Hook{
				ScriptPath: "/usr/sbin/usermod",
				Arguments:  []string{"-G", "sudo", "{username}"},
			},
			GetUserGroups: Hook{
				ScriptPath: "/usr/bin/groups",
				Arguments:  []string{"{username}"},
			},
		},
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(defaultConfig); err != nil {
		return err
	}

	return nil
}

func handleCreateConfig() {
	createConfigFlags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	pathToConfig := createConfigFlags.String("path", defaultConfigFilePath, "Path to save the configuration file")
	createConfigFlags.Parse(os.Args[2:])

	if err := createDefaultConfig(*pathToConfig); err != nil {
		log.Fatalf("Failed to create config file: %v", err)
	}
	fmt.Printf("Configuration file template created at: %s\n", *pathToConfig)
}

func testModePromptAndSetPAMEnv() {

	createConfigFlags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	createConfigFlags.StringVar(&configFilePath, "config", defaultConfigFilePath, "Path to configuration file")
	createConfigFlags.Parse(os.Args[2:])

	fmt.Print("Enter PAM_USER: ")
	var user string
	fmt.Scanln(&user)
	os.Setenv("PAM_USER", user)
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Printf("\nSubcommands: \n\tcreate-config\n\ttest\n\tversion\n")
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "create-config":
			handleCreateConfig()
			return
		case "test":
			testMode = true
			testModePromptAndSetPAMEnv()
		case "version":
			fmt.Println(Version)
			return
		default:
			flag.StringVar(&configFilePath, "config", defaultConfigFilePath, "Path to configuration file")
			flag.BoolVar(&showVersion, "version", false, "Show version and exit")
			flag.Parse()
		}
	}

	if showVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	if configFilePath == "" {
		// try env instead
		if envConfig := os.Getenv("PAM_OIDC_CONFIG"); envConfig != "" {
			configFilePath = envConfig
		}
	}

	// Load configuration
	config = loadConfigFromFile()

	if config == nil {
		fmt.Fprintln(os.Stderr, "Failed to load configuration file from ", configFilePath)
		os.Exit(1)
	}

	// Initialize logging
	initLogging()
	defer logFile.Close()

	// Clean up expired lock files
	if err := cleanupExpiredLocks(); err != nil {
		logWarn("Failed to cleanup expired locks: %v", err)
		// Don't fail initialization for cleanup errors
	}

	// Setup signal handling
	setupSignalHandling()

	// Load PAM environment
	pamEnv = loadPAMEnvironment()

	logDebug("=== SCRIPT START ===")
	logDebug("PAM_USER: '%s'", pamEnv.User)
	logDebug("PAM_SERVICE: '%s'", pamEnv.Service)
	logDebug("PAM_RHOST: '%s'", pamEnv.RHost)
	logDebug("PAM_TTY: '%s'", pamEnv.TTY)

	// Validate required parameters
	if pamEnv.User == "" {
		logError("Username validation failed - PAM_USER is empty")
		errorExit("Username not provided (PAM_USER not set)")
	}

	logInfo("Authentication attempt - User: %s, Service: %s, TTY: %s, RHost: %s",
		pamEnv.User, pamEnv.Service, pamEnv.TTY, pamEnv.RHost)

	// Check if SSO is enabled
	if !config.EnableSSO {
		logWarn("SSO disabled, skipping authentication")
		os.Exit(1)
	}

	// Perform device flow authentication
	if err := authenticateDeviceFlow(); err != nil {
		logError("Authentication failed: %v", err)
		removeAuthLock()
		os.Exit(1)
	}
	removeAuthLock()
	logInfo("Authentication successful for user: %s", pamEnv.User)
	fmt.Fprintln(os.Stderr, "Authentication successful!")
	os.Exit(0)
}

func loadConfigFromFile() *Config {
	file, err := os.Open(configFilePath)
	if err != nil {
		logError("Failed to open config file: %v", err)
		return nil
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		logError("Failed to decode config file: %v", err)
		return nil
	}

	return &config
}

func initLogging() {
	// Map log level string to number
	switch config.LogLevel {
	case "error":
		logLevel = LogLevelError
	case "warn":
		logLevel = LogLevelWarn
	case "info":
		logLevel = LogLevelInfo
	case "debug":
		logLevel = LogLevelDebug
	default:
		logLevel = LogLevelInfo
	}
	// Open log file if not in test mode
	if !testMode {
		var err error
		logFile, err = os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
	}
}

func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)

	go func() {
		<-c
		logInfo("Authentication cancelled or client disconnected")
		os.Exit(1)
	}()
}

func loadPAMEnvironment() *PAMEnv {
	return &PAMEnv{
		User:    os.Getenv("PAM_USER"),
		Service: os.Getenv("PAM_SERVICE"),
		RHost:   os.Getenv("PAM_RHOST"),
		TTY:     os.Getenv("PAM_TTY"),
	}
}

func logMessage(level int, format string, args ...interface{}) {
	if level <= logLevel {
		levelStr := map[int]string{
			LogLevelError: "error",
			LogLevelWarn:  "warn",
			LogLevelInfo:  "info",
			LogLevelDebug: "debug",
		}[level]

		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)
		logLine := fmt.Sprintf("%s [PAM_OIDC:%s] %s\n", timestamp, levelStr, message)
		// if test mode is on print only to console
		if testMode {
			fmt.Print(logLine)
			return
		}

		logFile.WriteString(logLine)
		logFile.Sync()

	}
}

func logError(format string, args ...interface{}) { logMessage(LogLevelError, format, args...) }
func logWarn(format string, args ...interface{})  { logMessage(LogLevelWarn, format, args...) }

func logInfo(format string, args ...interface{})  { logMessage(LogLevelInfo, format, args...) }
func logDebug(format string, args ...interface{}) { logMessage(LogLevelDebug, format, args...) }

func errorExit(message string) {
	logError(message)
	os.Exit(1)
}

func authenticateDeviceFlow() error {
	logDebug("Starting device flow authentication")

	// Initialize OIDC provider (discovery + endpoints) before authentication
	if err := initializeOIDCProvider(); err != nil {
		return fmt.Errorf("failed to initialize OIDC provider: %v", err)
	}

	// Check for existing valid auth session first
	authLock, isExisting, err := checkOrCreateAuthLock()
	if err != nil {
		return fmt.Errorf("failed to check/create auth lock: %v", err)
	}

	// Display authentication instructions (using auth lock data)
	displayAuthInstructionsFromLock(authLock, isExisting)

	// Start new polling session (update ID to supersede any old polling)
	if err := updatePollingID(authLock); err != nil {
		return fmt.Errorf("failed to start polling session: %v", err)
	}

	// Poll for token (using device code from lock)
	tokenResponse, err := pollForTokenResponseFromLock(config.OIDCProvider.OIDCTokenURL, authLock)
	if err != nil {
		return fmt.Errorf("token polling failed: %v", err)
	}

	// Validate token and get user info
	logDebug("Validating token and retrieving user info")
	// Validate JWT and extract claims using OAuth2-based flexible mapping
	extractedClaims, err := ValidateAndExtractClaimsWithOAuth2(tokenResponse)
	if err != nil {
		return fmt.Errorf("token validation failed: %v", err)
	}

	// Verify username matches
	if extractedClaims.PreferredUsername != pamEnv.User {
		logError("Username mismatch - requested: %s, authenticated: %s",
			pamEnv.User, extractedClaims.PreferredUsername)
		fmt.Fprintln(os.Stderr, "Authentication failed - username mismatch")
		return fmt.Errorf("username mismatch")
	}

	// Check group membership if required
	if err := checkGroupMembershipFromClaims(extractedClaims); err != nil {
		return err
	}

	// check allowed users list if configured
	if len(config.AllowedUsers) > 0 {
		if !slices.Contains(config.AllowedUsers, pamEnv.User) {
			logWarn("User %s is not in the allowed users list", pamEnv.User)
			fmt.Fprintln(os.Stderr, "Authentication failed - user not allowed")
			return fmt.Errorf("user not allowed")
		}
	}

	// Ensure user exists locally
	if err := ensureLocalUser(); err != nil {
		return err
	}

	// Setup sudo privileges if user is an administrator in current system
	if err := setupSudoPrivilegesFromClaims(extractedClaims); err != nil {
		logWarn("Failed to setup sudo privileges: %v", err)
		// Don't fail authentication for sudo setup issues
	}
	// Authentication successful - force remove lock file (cleanup regardless of PID)
	return nil
}

func requestDeviceAuthorization(deviceAuthURL string) (*DeviceAuthResponse, error) {
	logDebug("POST %s", deviceAuthURL)

	data := url.Values{}
	data.Set("client_id", config.OIDCProvider.ClientID)
	data.Set("scope", "openid")

	resp, err := httpClient.PostForm(deviceAuthURL, data)
	if err != nil {
		logError("Failed to contact OIDC device endpoint: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	logDebug("Device response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		logError("Device authorization failed with status %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("device authorization failed with status %d", resp.StatusCode)
	}

	var deviceResp DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		logError("Failed to parse device authorization response: %v", err)
		return nil, err
	}

	// Validate response
	if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" || deviceResp.VerificationURI == "" {
		logError("Invalid device authorization response")
		return nil, fmt.Errorf("invalid device authorization response")
	}

	return &deviceResp, nil
}

// displayAuthInstructionsFromLock shows auth instructions using lock file data
func displayAuthInstructionsFromLock(authLock *AuthLock, isExisting bool) {
	expiresAt, _ := time.Parse(time.RFC3339, authLock.ExpiresAt)
	remainingTime := int(time.Until(expiresAt).Seconds())
	if remainingTime < 0 {
		remainingTime = 0
	}

	// multiline string
	banner := fmt.Sprintf(`
Please complete authentication in your web browser:   
   
1. Visit: %s
2. Enter code: %s
    
Or open directly:
%s
  
Waiting for authentication... (timeout: %ds)

`, authLock.VerificationURI, authLock.UserCode, authLock.VerificationURIComplete, remainingTime)

	fmt.Fprintln(os.Stderr, banner)

	if isExisting {
		logInfo("Resumed existing auth session for user %s", authLock.User)
	} else {
		logDebug("Device code displayed for user authentication")
	}
	logDebug("Device code displayed - Code: %s, URI: %s", authLock.UserCode, authLock.VerificationURI)
}

func ensureLocalUser() error {
	// Check if user exists
	if _, err := user.Lookup(pamEnv.User); err == nil {
		logDebug("User %s already exists locally", pamEnv.User)
		return nil
	}

	if !config.CreateLocalUsers {
		logError("User %s does not exist locally and auto-creation is disabled", pamEnv.User)
		fmt.Fprintln(os.Stderr, "Authentication failed - user does not exist")
		return fmt.Errorf("user does not exist and auto-creation disabled")
	}

	logInfo("User %s does not exist locally, creating user", pamEnv.User)

	// Create user with home directory
	args := config.SystemHooks.AddUser.FormatUserArg(pamEnv.User)
	cmd := exec.Command(config.SystemHooks.AddUser.ScriptPath, args...)
	if err := cmd.Run(); err != nil {
		logError("Failed to create user %s: %v", pamEnv.User, err)
		fmt.Fprintln(os.Stderr, "Authentication failed - could not create user")
		return fmt.Errorf("failed to create user: %v", err)
	}

	logInfo("Successfully created user %s", pamEnv.User)

	// Run post-user-creation hook if configured
	if config.SystemHooks.PostUserCreation.ScriptPath != "" {
		logDebug("Running post-user-creation hook for user %s", pamEnv.User)
		args := config.SystemHooks.PostUserCreation.FormatUserArg(pamEnv.User)
		cmd := exec.Command(config.SystemHooks.PostUserCreation.ScriptPath, args...)
		if err := cmd.Run(); err != nil {
			logWarn("Post-user-creation hook failed for user %s: %v", pamEnv.User, err)
			// Don't fail authentication - user creation succeeded, this is just system integration
		} else {
			logDebug("Post-user-creation hook completed successfully for user %s", pamEnv.User)
		}
	}

	return nil
}

func isUserInSudoGroup(username string) (bool, error) {
	args := config.SystemHooks.GetUserGroups.FormatUserArg(username)
	cmd := exec.Command(config.SystemHooks.GetUserGroups.ScriptPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to get groups for user %s: %v", username, err)
	}
	groups := strings.Fields(string(output))
	return slices.Contains(groups, config.SudoGroupName), nil
}

// addUserToSudoersFile adds a user entry to the shared sudoers file
func addUserToSudoersFile(sudoersFile, username string) error {
	userLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL", username)

	// Read existing content
	content, err := os.ReadFile(sudoersFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read sudoers file: %v", err)
	}

	lines := []string{}
	if len(content) > 0 {
		lines = strings.Split(string(content), "\n")
	}

	// Check if user already exists
	userExists := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), username+" ") {
			// Update existing line
			lines[i] = userLine
			userExists = true
			break
		}
	}

	// Add user if not exists
	if !userExists {
		if len(lines) == 0 || lines[0] == "" {
			lines = []string{
				"# PAM OIDC authenticated users with sudo privileges",
				"# Managed automatically - do not edit manually",
				userLine,
			}
		} else {
			lines = append(lines, userLine)
		}
	}

	// Write back to file
	newContent := strings.Join(lines, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	return os.WriteFile(sudoersFile, []byte(newContent), 0440)
}

// removeUserFromSudoersFile removes a user entry from the shared sudoers file
func removeUserFromSudoersFile(sudoersFile, username string) error {
	// Read existing content
	content, err := os.ReadFile(sudoersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to remove
		}
		return fmt.Errorf("failed to read sudoers file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	newLines := []string{}
	userRemoved := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, username+" ") {
			userRemoved = true
			continue // Skip this line (remove it)
		}
		newLines = append(newLines, line)
	}

	if !userRemoved {
		return nil // User wasn't in the file
	}

	// Remove empty lines at the end and clean up
	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	// If only header comments remain, remove the file
	onlyComments := true
	for _, line := range newLines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			onlyComments = false
			break
		}
	}

	if onlyComments || len(newLines) == 0 {
		return os.Remove(sudoersFile)
	}

	newContent := strings.Join(newLines, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	return os.WriteFile(sudoersFile, []byte(newContent), 0440)
}
