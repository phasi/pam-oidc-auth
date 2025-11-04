package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

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

// generateID creates a simple random ID for polling identification
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// validateLockDir checks if lock directory is configured and creates it if needed
func validateLockDir() error {
	if config.LockDir == "" {
		return fmt.Errorf("lock directory not configured")
	}
	// Create lock directory if it doesn't exist
	if err := os.MkdirAll(config.LockDir, 0755); err != nil {
		return fmt.Errorf("failed to create lock directory: %v", err)
	}
	return nil
}

// getLockFilePath returns the lock file path for the current user
func getLockFilePath() string {
	return filepath.Join(config.LockDir, fmt.Sprintf("%s.lock", pamEnv.User))
}

// checkOrCreateAuthLock checks for existing valid auth session, or creates new one
func checkOrCreateAuthLock() (*AuthLock, bool, error) {
	if err := validateLockDir(); err != nil {
		return nil, false, err
	}

	lockFile := getLockFilePath()

	// Check if lock file already exists and is still valid
	if existingLock, err := loadExistingLock(lockFile); err == nil {
		if !isLockExpired(existingLock) {
			logInfo("Found existing valid auth session for user %s", pamEnv.User)
			return existingLock, true, nil
		} else {
			logDebug("Existing lock file expired, removing")
			os.Remove(lockFile)
		}
	}

	// No existing valid session, need to request new device authorization
	logDebug("Requesting new device authorization")
	deviceResp, err := requestDeviceAuthorization(config.OIDCProvider.OIDCDeviceAuthURL)
	if err != nil {
		return nil, false, fmt.Errorf("device authorization failed: %v", err)
	}

	// Create new lock file with device authorization
	now := time.Now()

	var expiresAt time.Time

	// Prefer module timeout if set
	if config.Timeout > 0 {
		expiresAt = now.Add(time.Duration(config.Timeout) * time.Second)
	} else {
		// Fall back to device code expiration from OIDC provider
		expiresAt = now.Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	}

	authLock := &AuthLock{
		User:                    pamEnv.User,
		PID:                     os.Getpid(),
		StartedAt:               now.Format(time.RFC3339),
		ExpiresAt:               expiresAt.Format(time.RFC3339),
		DeviceCode:              deviceResp.DeviceCode,
		UserCode:                deviceResp.UserCode,
		VerificationURI:         deviceResp.VerificationURI,
		VerificationURIComplete: deviceResp.VerificationURIComplete,
		PollingID:               generateID(),
	}

	// Write lock file atomically
	if err := writeAuthLock(lockFile, authLock); err != nil {
		return nil, false, fmt.Errorf("failed to create lock file: %v", err)
	}

	logDebug("Created new auth lock file for user %s (PID: %d)", pamEnv.User, os.Getpid())
	return authLock, false, nil
}

// loadExistingLock reads and validates an existing lock file
func loadExistingLock(lockFile string) (*AuthLock, error) {
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return nil, err
	}

	var authLock AuthLock
	if err := json.Unmarshal(data, &authLock); err != nil {
		return nil, fmt.Errorf("invalid lock file format: %v", err)
	}

	return &authLock, nil
}

// writeAuthLock writes the auth lock to file atomically
func writeAuthLock(lockFile string, authLock *AuthLock) error {
	data, err := json.MarshalIndent(authLock, "", "  ")
	if err != nil {
		return err
	}

	// Write to temporary file first, then rename (atomic operation)
	tempFile := lockFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tempFile, lockFile)
}

// isLockExpired checks if the auth lock has expired
func isLockExpired(authLock *AuthLock) bool {
	expiresAt, err := time.Parse(time.RFC3339, authLock.ExpiresAt)
	if err != nil {
		return true // If we can't parse time, consider it expired
	}
	return time.Now().After(expiresAt)
}

// updatePollingID generates a new polling ID and updates the lock file
func updatePollingID(authLock *AuthLock) error {
	if err := validateLockDir(); err != nil {
		return err
	}

	lockFile := getLockFilePath()

	// Generate new ID and update the lock
	authLock.PollingID = generateID()

	// Write updated lock file
	if err := writeAuthLock(lockFile, authLock); err != nil {
		return fmt.Errorf("failed to update polling ID: %v", err)
	}

	logDebug("Updated polling ID for user %s (new ID: %s)", pamEnv.User, authLock.PollingID[:8]+"...")
	return nil
}

// checkPollingID verifies if the polling ID still matches (polling session is active)
func checkPollingID(expectedID string) error {
	if config.LockDir == "" {
		return fmt.Errorf("lock directory not configured")
	}

	lockFile := getLockFilePath()

	authLock, err := loadExistingLock(lockFile)
	if err != nil {
		return fmt.Errorf("failed to read lock file: %v", err)
	}

	// Check if polling ID has changed
	if authLock.PollingID != expectedID {
		return fmt.Errorf("polling session cancelled - ID mismatch")
	}

	return nil
}

// removeAuthLock removes the authentication lock file regardless of PID
// Used when authentication succeeds or for cleanup after legitimate failures
func removeAuthLock() error {
	if config.LockDir == "" {
		return nil // Nothing to remove
	}

	lockFile := getLockFilePath()

	if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove lock file: %v", err)
	}

	logDebug("Removed auth lock file for user %s", pamEnv.User)
	return nil
}

// cleanupExpiredLocks removes expired lock files from the lock directory
func cleanupExpiredLocks() error {
	if config.LockDir == "" {
		return nil
	}

	entries, err := os.ReadDir(config.LockDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, nothing to clean
		}
		return fmt.Errorf("failed to read lock directory: %v", err)
	}

	cleaned := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".lock" {
			lockFile := filepath.Join(config.LockDir, entry.Name())
			if authLock, err := loadExistingLock(lockFile); err == nil {
				if isLockExpired(authLock) {
					if err := os.Remove(lockFile); err == nil {
						cleaned++
					}
				}
			} else {
				// Remove invalid lock files
				os.Remove(lockFile)
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		logDebug("Cleaned up %d expired/invalid lock files", cleaned)
	}

	return nil
}
