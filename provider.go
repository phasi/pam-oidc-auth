package main

// TokenSource specifies which token/endpoint contains specific claims
type TokenSource string

const (
	TokenSourceIDToken     TokenSource = "id_token"
	TokenSourceAccessToken TokenSource = "access_token"
	TokenSourceUserInfo    TokenSource = "userinfo"
	TokenSourceAuto        TokenSource = "auto" // Try multiple sources automatically
)

// ClaimSource defines where to find a specific claim and what it's called
type ClaimSource struct {
	ClaimName   string      `json:"claim_name"`   // Name of the claim in the token/response
	TokenSource TokenSource `json:"token_source"` // Which token/endpoint contains this claim
}

// ClaimMap tells us where to find different claims across various tokens and providers
type ClaimMap struct {
	// Configuration for username claim (PAM user will be matched against this)
	Username ClaimSource `json:"username"`
	// Configuration for groups claim
	Groups ClaimSource `json:"groups"`
	// Configuration for email claim (optional)
	Email ClaimSource `json:"email"`
	// Configuration for subject claim (optional)
	Subject ClaimSource `json:"subject"`

	// Fallback to fetching from userinfo endpoint if claims are missing (might not work in most cases)
	FallbackToUserInfo bool `json:"fallback_to_userinfo"`
}

type Provider struct {
	// OIDC Provider Configuration
	OIDCIssuerURL     string `json:"oidc_issuer_url"`
	OIDCDeviceAuthURL string `json:"oidc_device_auth_url"`
	OIDCTokenURL      string `json:"oidc_token_url"`
	OIDCUserInfoURL   string `json:"oidc_user_info_url"`
	JWKSUri           string `json:"jwks_uri"` // Manual JWKS URI (if not using discovery)

	// Client id for OIDC
	ClientID string `json:"oidc_client_id"`
	// Claim mapping configuration
	ClaimMap ClaimMap `json:"claim_map"`
	// enables automatic discovery of endpoints and JWKS URI
	UseDiscovery bool `json:"use_discovery"`
	// url where to fetch the OIDC discovery document
	AutoDiscoveryUrl string `json:"auto_discovery_url"`
}

// OIDC Discovery Document structure
type OIDCDiscovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// JWKS (JSON Web Key Set) structures
type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string   `json:"kty"` // Key type
	Kid string   `json:"kid"` // Key ID
	Use string   `json:"use"` // Key use
	Alg string   `json:"alg"` // Algorithm
	N   string   `json:"n"`   // RSA modulus
	E   string   `json:"e"`   // RSA exponent
	X5c []string `json:"x5c"` // X.509 certificate chain
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
