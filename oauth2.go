package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// ExtractedClaims represents the claims we need for authentication
type ExtractedClaims struct {
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	Sub               string   `json:"sub"`
}

// Token Response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"` // Added ID token for JWT validation
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// ID Token Claims (only standard OIDC claims + raw claims for flexible extraction)
type IDTokenClaims struct {
	// Standard OIDC claims (required for validation)
	Iss      string      `json:"iss"`                 // Issuer
	Sub      string      `json:"sub"`                 // Subject
	Aud      interface{} `json:"aud"`                 // Audience (can be string or []string)
	Exp      int64       `json:"exp"`                 // Expiration time
	Iat      int64       `json:"iat"`                 // Issued at
	AuthTime int64       `json:"auth_time,omitempty"` // Authentication time
	Nonce    string      `json:"nonce,omitempty"`     // Nonce

	// Raw claims map for flexible extraction based on ClaimMap configuration
	Claims map[string]interface{} `json:"-"` // All claims accessible by configured names
}

// TokenExtractor handles extracting claims from various token sources using standard libraries
type TokenExtractor struct {
	oauth2Config *oauth2.Config
	httpClient   *http.Client
}

// NewTokenExtractor creates a new token extractor with OAuth2 configuration
func NewTokenExtractor() *TokenExtractor {
	return &TokenExtractor{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ExtractClaimsFromTokenResponse extracts claims according to the configured ClaimMap
func (te *TokenExtractor) ExtractClaimsFromTokenResponse(tokenResponse *TokenResponse) (*ExtractedClaims, error) {
	// Convert our TokenResponse to oauth2.Token for standard library compatibility
	oauth2Token := &oauth2.Token{
		AccessToken: tokenResponse.AccessToken,
		TokenType:   tokenResponse.TokenType,
		Expiry:      time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
	}

	// Add ID token as extra field (oauth2 library supports this)
	if tokenResponse.IDToken != "" {
		oauth2Token = oauth2Token.WithExtra(map[string]interface{}{
			"id_token": tokenResponse.IDToken,
		})
	}

	result := &ExtractedClaims{}
	var errors []string

	// Extract username according to claim map
	username, err := te.extractClaim(oauth2Token, config.OIDCProvider.ClaimMap.Username, "string")
	if err != nil {
		errors = append(errors, fmt.Sprintf("username: %v", err))
	} else if usernameStr, ok := username.(string); ok {
		result.PreferredUsername = usernameStr
	}

	// Extract groups according to claim map
	groups, err := te.extractClaim(oauth2Token, config.OIDCProvider.ClaimMap.Groups, "array")
	if err != nil {
		logDebug("Groups extraction failed: %v", err)
		result.Groups = []string{} // Continue with empty groups
	} else if groupsArray, ok := groups.([]string); ok {
		result.Groups = groupsArray
	}

	// Extract email according to claim map
	email, err := te.extractClaim(oauth2Token, config.OIDCProvider.ClaimMap.Email, "string")
	if err != nil {
		logDebug("Email extraction failed: %v", err)
	} else if emailStr, ok := email.(string); ok {
		result.Email = emailStr
	}

	// Extract subject according to claim map
	subject, err := te.extractClaim(oauth2Token, config.OIDCProvider.ClaimMap.Subject, "string")
	if err != nil {
		logDebug("Subject extraction failed: %v", err)
	} else if subjectStr, ok := subject.(string); ok {
		result.Sub = subjectStr
	}

	// Check if we have minimum required information
	if result.PreferredUsername == "" {
		if len(errors) > 0 {
			return nil, fmt.Errorf("failed to extract required claims: %s", strings.Join(errors, ", "))
		}
		return nil, fmt.Errorf("username claim is empty")
	}

	logDebug("Successfully extracted claims for user: %s (groups: %d)", result.PreferredUsername, len(result.Groups))
	return result, nil
}

// extractClaim extracts a single claim according to the ClaimSource configuration
func (te *TokenExtractor) extractClaim(token *oauth2.Token, claimSource ClaimSource, expectedType string) (interface{}, error) {
	if claimSource.ClaimName == "" {
		return nil, fmt.Errorf("claim name not configured")
	}

	var attempts []string
	var lastError error

	// Determine which sources to try based on configuration
	sources := te.getSourcesAttemptOrder(claimSource.TokenSource)

	for _, source := range sources {
		attempts = append(attempts, string(source))

		var result interface{}
		var err error

		switch source {
		case TokenSourceIDToken:
			result, err = te.extractFromIDToken(token, claimSource.ClaimName, expectedType)
		case TokenSourceAccessToken:
			result, err = te.extractFromAccessToken(token, claimSource.ClaimName, expectedType)
		case TokenSourceUserInfo:
			result, err = te.extractFromUserInfo(token, claimSource.ClaimName, expectedType)
		default:
			err = fmt.Errorf("unsupported token source: %s", source)
		}

		if err == nil && result != nil {
			logDebug("Successfully extracted claim '%s' from %s", claimSource.ClaimName, source)
			return result, nil
		}

		lastError = err
		logDebug("Failed to extract claim '%s' from %s: %v", claimSource.ClaimName, source, err)
	}

	return nil, fmt.Errorf("claim '%s' not found in any of the attempted sources [%s]: %v",
		claimSource.ClaimName, strings.Join(attempts, ", "), lastError)
}

// getSourcesAttemptOrder returns the order of sources to attempt based on configuration
func (te *TokenExtractor) getSourcesAttemptOrder(configuredSource TokenSource) []TokenSource {
	switch configuredSource {
	case TokenSourceIDToken:
		return []TokenSource{TokenSourceIDToken}
	case TokenSourceAccessToken:
		return []TokenSource{TokenSourceAccessToken}
	case TokenSourceUserInfo:
		return []TokenSource{TokenSourceUserInfo}
	case TokenSourceAuto:
		// Auto mode: try ID token first, then access token, then userinfo
		sources := []TokenSource{TokenSourceIDToken, TokenSourceAccessToken}
		if config.OIDCProvider.ClaimMap.FallbackToUserInfo {
			sources = append(sources, TokenSourceUserInfo)
		}
		return sources
	default:
		// Default to auto behavior
		return []TokenSource{TokenSourceIDToken, TokenSourceAccessToken}
	}
}

// extractFromIDToken extracts a claim from the ID token with proper JWT validation
func (te *TokenExtractor) extractFromIDToken(token *oauth2.Token, claimName string, expectedType string) (interface{}, error) {
	idTokenRaw := te.getIDTokenFromOAuth2Token(token)
	if idTokenRaw == "" {
		return nil, fmt.Errorf("no ID token available")
	}

	// Parse and validate the ID token using cached JWKS
	claims, err := parseAndValidateIDToken(idTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("ID token validation failed: %w", err)
	}

	// Extract the specific claim
	return te.extractClaimFromParsedClaims(claims.Claims, claimName, expectedType)
}

// extractFromAccessToken extracts a claim from the access token (no signature validation needed)
func (te *TokenExtractor) extractFromAccessToken(token *oauth2.Token, claimName string, expectedType string) (interface{}, error) {
	// Parse access token without validation (for claim extraction only)
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("access token claims are not in expected format")
	}

	return te.extractClaimFromParsedClaims(claims, claimName, expectedType)
}

// extractFromUserInfo extracts a claim from the userinfo endpoint
func (te *TokenExtractor) extractFromUserInfo(token *oauth2.Token, claimName string, expectedType string) (interface{}, error) {
	// Create request to userinfo endpoint
	req, err := http.NewRequest("GET", config.OIDCProvider.OIDCUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	// Make the request
	resp, err := te.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return te.extractClaimFromParsedClaims(userInfo, claimName, expectedType)
}

// extractClaimFromParsedClaims extracts and converts a claim from parsed claims
func (te *TokenExtractor) extractClaimFromParsedClaims(claims map[string]interface{}, claimName string, expectedType string) (interface{}, error) {
	value, exists := claims[claimName]
	if !exists {
		return nil, fmt.Errorf("claim '%s' not found", claimName)
	}

	if value == nil {
		return nil, fmt.Errorf("claim '%s' is null", claimName)
	}

	switch expectedType {
	case "string":
		if strValue, ok := value.(string); ok {
			return strValue, nil
		}
		return nil, fmt.Errorf("claim '%s' is not a string, got %T", claimName, value)

	case "array":
		return convertToStringArray(value)

	default:
		return value, nil
	}
}

// getIDTokenFromOAuth2Token extracts ID token from oauth2.Token extra fields
func (te *TokenExtractor) getIDTokenFromOAuth2Token(token *oauth2.Token) string {
	if idToken := token.Extra("id_token"); idToken != nil {
		if idTokenStr, ok := idToken.(string); ok {
			return idTokenStr
		}
	}
	return ""
}

// Global token extractor instance
var globalTokenExtractor *TokenExtractor

// initTokenExtractor initializes the global token extractor
func initTokenExtractor() {
	if globalTokenExtractor == nil {
		globalTokenExtractor = NewTokenExtractor()
	}
}

// ValidateAndExtractClaimsWithOAuth2 is the new main function that replaces validateAndExtractClaims
// It uses proper OAuth2 library and flexible claim mapping
func ValidateAndExtractClaimsWithOAuth2(tokenResponse *TokenResponse) (*ExtractedClaims, error) {
	initTokenExtractor()
	return globalTokenExtractor.ExtractClaimsFromTokenResponse(tokenResponse)
}

// Global variables for caching OIDC discovery and JWKS
var (
	cachedDiscovery *OIDCDiscovery
	cachedJWKS      *JWKS
)

// initializeOIDCProvider initializes OIDC provider configuration for JWT validation
func initializeOIDCProvider() error {
	// Skip if already initialized
	if cachedJWKS != nil {
		return nil
	}

	var err error
	var jwksUri string

	if config.OIDCProvider.UseDiscovery && config.OIDCProvider.AutoDiscoveryUrl != "" {
		logDebug("Using OIDC discovery for JWT validation")

		// Fetch discovery document
		cachedDiscovery, err = discoverOIDCConfiguration(config.OIDCProvider.AutoDiscoveryUrl)
		if err != nil {
			return fmt.Errorf("OIDC discovery failed: %w", err)
		}

		// Populate Provider endpoints from discovery (if not manually set)
		if config.OIDCProvider.OIDCDeviceAuthURL == "" && cachedDiscovery.DeviceAuthorizationEndpoint != "" {
			config.OIDCProvider.OIDCDeviceAuthURL = cachedDiscovery.DeviceAuthorizationEndpoint
			logDebug("Set device auth URL from discovery: %s", config.OIDCProvider.OIDCDeviceAuthURL)
		}
		if config.OIDCProvider.OIDCTokenURL == "" && cachedDiscovery.TokenEndpoint != "" {
			config.OIDCProvider.OIDCTokenURL = cachedDiscovery.TokenEndpoint
			logDebug("Set token URL from discovery: %s", config.OIDCProvider.OIDCTokenURL)
		}
		if config.OIDCProvider.OIDCUserInfoURL == "" && cachedDiscovery.UserinfoEndpoint != "" {
			config.OIDCProvider.OIDCUserInfoURL = cachedDiscovery.UserinfoEndpoint
			logDebug("Set userinfo URL from discovery: %s", config.OIDCProvider.OIDCUserInfoURL)
		}
		if config.OIDCProvider.OIDCIssuerURL == "" && cachedDiscovery.Issuer != "" {
			config.OIDCProvider.OIDCIssuerURL = cachedDiscovery.Issuer
			logDebug("Set issuer URL from discovery: %s", config.OIDCProvider.OIDCIssuerURL)
		}

		jwksUri = cachedDiscovery.JwksUri
	} else {
		// Use manual JWKS URI
		jwksUri = config.OIDCProvider.JWKSUri
		logDebug("Using manual JWKS URI for JWT validation: %s", jwksUri)
	}

	// Fetch JWKS for token validation
	if jwksUri != "" {
		logDebug("Fetching JWKS for token validation")
		cachedJWKS, err = fetchJWKS(jwksUri)
		if err != nil {
			return fmt.Errorf("JWKS fetch failed: %w", err)
		}
	} else {
		return fmt.Errorf("JWKS URI not available - set 'jwks_uri' in config or enable 'use_discovery'")
	}

	return nil
}

// discoverOIDCConfiguration fetches the OIDC discovery document
func discoverOIDCConfiguration(issuerURL string) (*OIDCDiscovery, error) {
	discoveryURL := issuerURL

	logDebug("Fetching OIDC discovery from: %s", discoveryURL)

	resp, err := httpClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OIDC discovery request failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC discovery response: %w", err)
	}

	var discovery OIDCDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC discovery document: %w", err)
	}

	logDebug("OIDC discovery successful. JWKS URI: %s", discovery.JwksUri)
	return &discovery, nil
}

// fetchJWKS fetches the JSON Web Key Set from the provider
func fetchJWKS(jwksUri string) (*JWKS, error) {
	logDebug("Fetching JWKS from: %s", jwksUri)

	resp, err := httpClient.Get(jwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	logDebug("JWKS fetched successfully. Found %d keys", len(jwks.Keys))
	return &jwks, nil
}

// parseAndValidateIDToken parses and validates the ID token
func parseAndValidateIDToken(idToken string) (*IDTokenClaims, error) {
	// Parse the token header to get the key ID
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the key ID from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token header missing 'kid' field")
		}

		// Find the corresponding JWK
		publicKey, err := getPublicKeyFromJWKS(cachedJWKS, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key for kid '%s': %w", kid, err)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse/validate ID token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("ID token is invalid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from ID token")
	}

	// Validate standard claims
	if err := validateStandardClaims(claims, config.OIDCProvider.OIDCIssuerURL, config.OIDCProvider.ClientID); err != nil {
		return nil, fmt.Errorf("ID token validation failed: %w", err)
	}

	// Convert to our IDTokenClaims structure
	idTokenClaims, err := convertToIDTokenClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to convert claims: %w", err)
	}

	logDebug("ID token validated successfully for subject: %s", idTokenClaims.Sub)
	return idTokenClaims, nil
}

// getPublicKeyFromJWKS extracts the RSA public key from JWKS for the given key ID
func getPublicKeyFromJWKS(jwks *JWKS, kid string) (*rsa.PublicKey, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			// Decode the RSA modulus and exponent
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
			}

			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
			}

			// Create the public key
			n := new(big.Int).SetBytes(nBytes)
			e := 0
			for _, b := range eBytes {
				e = e<<8 + int(b)
			}

			return &rsa.PublicKey{N: n, E: e}, nil
		}
	}

	return nil, fmt.Errorf("no RSA key found for kid: %s", kid)
}

// validateStandardClaims validates the standard OIDC claims
func validateStandardClaims(claims jwt.MapClaims, expectedIssuer string, expectedAudience string) error {
	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid 'iss' claim")
	}
	if iss != expectedIssuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, iss)
	}

	// Validate audience
	audClaim := claims["aud"]
	var audiences []string
	switch v := audClaim.(type) {
	case string:
		audiences = []string{v}
	case []interface{}:
		for _, aud := range v {
			if audStr, ok := aud.(string); ok {
				audiences = append(audiences, audStr)
			}
		}
	default:
		return fmt.Errorf("invalid 'aud' claim type")
	}

	audienceValid := false
	for _, aud := range audiences {
		if aud == expectedAudience {
			audienceValid = true
			break
		}
	}
	if !audienceValid {
		return fmt.Errorf("invalid audience: expected %s, got %v", expectedAudience, audiences)
	}

	// Validate expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing or invalid 'exp' claim")
	}
	if time.Now().Unix() > int64(exp) {
		return fmt.Errorf("token has expired")
	}

	// Validate issued at (iat) - should not be in the future
	if iat, ok := claims["iat"].(float64); ok {
		if time.Now().Unix() < int64(iat)-300 { // 5 minute clock skew tolerance
			return fmt.Errorf("token issued in the future")
		}
	}

	return nil
}

// convertToIDTokenClaims converts jwt.MapClaims to our IDTokenClaims structure
// Only extracts standard OIDC claims, all other claims are accessible via Claims map
func convertToIDTokenClaims(claims jwt.MapClaims) (*IDTokenClaims, error) {
	idTokenClaims := &IDTokenClaims{
		Claims: make(map[string]interface{}),
	}

	// Copy all claims to the Claims map for flexible extraction based on ClaimMap
	for k, v := range claims {
		idTokenClaims.Claims[k] = v
	}

	// Extract only standard OIDC claims (required for validation)
	if iss, ok := claims["iss"].(string); ok {
		idTokenClaims.Iss = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		idTokenClaims.Sub = sub
	}
	if aud := claims["aud"]; aud != nil {
		idTokenClaims.Aud = aud
	}
	if exp, ok := claims["exp"].(float64); ok {
		idTokenClaims.Exp = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		idTokenClaims.Iat = int64(iat)
	}
	if authTime, ok := claims["auth_time"].(float64); ok {
		idTokenClaims.AuthTime = int64(authTime)
	}
	if nonce, ok := claims["nonce"].(string); ok {
		idTokenClaims.Nonce = nonce
	}

	// Note: Custom claims like username, email, groups are NOT extracted here
	// They are accessed dynamically via Claims map using configured claim names

	return idTokenClaims, nil
}

// convertToStringArray converts various claim formats to string array
// Used by oauth2.go for flexible claim processing
func convertToStringArray(value interface{}) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}

	switch v := value.(type) {
	case []string:
		return v, nil
	case []interface{}:
		var result []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, nil
	case string:
		// Handle comma-separated string
		if v == "" {
			return []string{}, nil
		}
		return strings.Split(v, ","), nil
	default:
		return nil, fmt.Errorf("value is not a string array or comma-separated string")
	}
}

// Polling function that returns full TokenResponse for JWT validation
func pollForTokenResponseFromLock(tokenURL string, authLock *AuthLock) (*TokenResponse, error) {
	pollInterval := config.PollInterval
	if pollInterval == 0 {
		pollInterval = 5 // Default fallback
	}

	// Calculate remaining timeout from lock expiration
	expiresAt, err := time.Parse(time.RFC3339, authLock.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration time in lock: %v", err)
	}

	remainingTime := time.Until(expiresAt)
	if remainingTime <= 0 {
		return nil, fmt.Errorf("auth session expired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), remainingTime)
	defer cancel()

	ticker := time.NewTicker(time.Duration(pollInterval) * time.Second)
	defer ticker.Stop()

	// // Additional ticker for more frequent connection checks (every 1 second)
	// connectionTicker := time.NewTicker(1 * time.Second)
	// defer connectionTicker.Stop()

	logDebug("Starting token polling from lock with PPID: %d", os.Getppid())

	for {
		select {
		case <-ctx.Done():
			logError("Authentication timeout - no token received")
			fmt.Fprintln(os.Stderr, "Authentication timeout")
			return nil, fmt.Errorf("authentication timeout")
		// case <-connectionTicker.C:
		// 	// Frequent check for ID changes (cancelled by new login attempt)
		// 	if err := checkPollingID(authLock.PollingID); err != nil {
		// 		logInfo("Polling session cancelled: %v", err)
		// 		return nil, err
		// 	}
		case <-ticker.C:
			// Check if polling ID still matches before polling
			if err := checkPollingID(authLock.PollingID); err != nil {
				logInfo("Polling session cancelled: %v", err)
				return nil, err
			}

			logDebug("Polling for token")

			data := url.Values{}
			data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			data.Set("device_code", authLock.DeviceCode)
			data.Set("client_id", config.OIDCProvider.ClientID)

			resp, err := httpClient.PostForm(tokenURL, data)
			if err != nil {
				logDebug("Token request failed: %v", err)
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				logDebug("Failed to read token response: %v", err)
				continue
			}

			var tokenResp TokenResponse
			if err := json.Unmarshal(body, &tokenResp); err != nil {
				logDebug("Failed to parse token response: %v", err)
				continue
			}

			// Handle different error conditions
			switch tokenResp.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				pollInterval += 2
				ticker.Reset(time.Duration(pollInterval) * time.Second)
				continue
			case "expired_token":
				logWarn("Device code expired")
				fmt.Fprintln(os.Stderr, "Authentication timeout - device code expired")
				return nil, fmt.Errorf("device code expired")
			case "access_denied":
				logWarn("Access denied by user")
				fmt.Fprintln(os.Stderr, "Authentication denied")
				return nil, fmt.Errorf("access denied")
			case "":
				// No error, check for tokens
				if tokenResp.AccessToken != "" {
					logDebug("Token response received successfully")
					logDebug("Access token: %s", tokenResp.AccessToken)
					logDebug("ID token: %s", tokenResp.IDToken)
					if tokenResp.IDToken != "" {
						logDebug("ID token present in response")
					} else {
						logWarn("ID token not present in response - will fallback to userinfo if enabled")
					}
					return &tokenResp, nil
				}
			default:
				logError("Token request failed with error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
				return nil, fmt.Errorf("token request failed: %s", tokenResp.Error)
			}
		}
	}
}

// Helper functions to adapt ExtractedClaims to existing authentication flow

// checkGroupMembershipFromClaims checks group membership using ExtractedClaims
func checkGroupMembershipFromClaims(extractedClaims *ExtractedClaims) error {
	if len(config.RequiredGroupsAny) == 0 && len(config.RequiredGroupsAll) == 0 {
		return nil
	}

	hasRequiredGroupAny := false

	if len(config.RequiredGroupsAny) == 0 {
		hasRequiredGroupAny = true
	} else {
		for _, requiredGroup := range config.RequiredGroupsAny {
			hasRequiredGroupAny = slices.Contains(extractedClaims.Groups, requiredGroup)
			if hasRequiredGroupAny {
				break
			}
		}
	}

	hasRequiredGroupAll := true
	for _, requiredGroup := range config.RequiredGroupsAll {
		found := slices.Contains(extractedClaims.Groups, requiredGroup)
		if !found {
			hasRequiredGroupAll = false
			break
		}
	}

	if !hasRequiredGroupAny && !hasRequiredGroupAll {
		logWarn("User %s does not have required group membership", pamEnv.User)

		banner := `
Access denied!

You do not have permission to access this system.
Contact your administrator for access.

`
		fmt.Fprintln(os.Stderr, banner)
		return fmt.Errorf("insufficient group membership")
	}

	return nil
}

// setupSudoPrivilegesFromClaims manages sudo privileges using ExtractedClaims
func setupSudoPrivilegesFromClaims(extractedClaims *ExtractedClaims) error {
	if config.AdminGroupName == "" {
		logDebug("No administrator group configured, skipping sudo privileges setup")
		return nil
	}

	// Check if user is in the administrator group
	var canSudo bool
	for _, group := range extractedClaims.Groups {
		if group == config.AdminGroupName {
			canSudo = true
			break
		}
	}

	inSudoGroup, checkSudoErr := isUserInSudoGroup(pamEnv.User)
	if checkSudoErr != nil {
		logWarn("Failed to check if user %s is in sudo group: %v", pamEnv.User, checkSudoErr)
		// No reason to fail authentication here
	}

	if canSudo {

		if inSudoGroup {
			logDebug("User %s is already in sudo group, no action needed", pamEnv.User)
			return nil
		}

		logInfo("User %s is in administrator group %s, adding sudo privileges", pamEnv.User, config.AdminGroupName)

		// Add user to sudo group
		args := config.SystemHooks.AddUserToSudoGroup.FormatUserArg(pamEnv.User)
		cmd := exec.Command(config.SystemHooks.AddUserToSudoGroup.ScriptPath, args...)
		if err := cmd.Run(); err != nil {
			logError("Failed to add user %s to sudo group: %v", pamEnv.User, err)
			// Don't fail authentication if sudo group addition fails
		} else {
			logInfo("Added user %s to sudo group", pamEnv.User)
		}

		// Add user to sudoers file
		if err := addUserToSudoersFile(config.SudoersFile, pamEnv.User); err != nil {
			logError("Failed to add user %s to sudoers file: %v", pamEnv.User, err)
		} else {
			logInfo("Added user %s to sudoers file %s", pamEnv.User, config.SudoersFile)
		}
	} else {

		// Return early unless for some reason we couldn't check sudo group membership earlier
		if !inSudoGroup && checkSudoErr == nil {
			logDebug("User %s is not in sudo group, no action needed", pamEnv.User)
			return nil
		}

		logDebug("User %s is not in administrator group %s, removing sudo privileges", pamEnv.User, config.AdminGroupName)

		// Remove user from sudo group
		args := config.SystemHooks.RemoveUserFromSudoGroup.FormatUserArg(pamEnv.User)
		cmd := exec.Command(config.SystemHooks.RemoveUserFromSudoGroup.ScriptPath, args...)
		if err := cmd.Run(); err != nil {
			logDebug("Failed to remove user %s from sudo group (may not be in group): %v", pamEnv.User, err)
			// This is expected if user was never in sudo group
		} else {
			logInfo("Removed user %s from sudo group", pamEnv.User)
		}

		// Remove user from sudoers file
		if err := removeUserFromSudoersFile(config.SudoersFile, pamEnv.User); err != nil {
			logError("Failed to remove user %s from sudoers file: %v", pamEnv.User, err)
		} else {
			logInfo("Removed user %s from sudoers file %s", pamEnv.User, config.SudoersFile)
		}
	}

	return nil
}
