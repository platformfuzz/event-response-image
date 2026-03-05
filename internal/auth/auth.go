package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/golang-jwt/jwt/v5"
)

var debugEnabled = os.Getenv("DEBUG") == "true"

func debugLog(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf("DEBUG - "+format, v...)
	}
}

// Cognito client and cache
var (
	cognitoClient   *cognitoidentityprovider.Client
	cognitoClientOnce sync.Once
	userPoolID     string

	groupCache = struct {
		sync.RWMutex
		data map[string]cachedGroups
	}{
		data: make(map[string]cachedGroups),
	}
)

type cachedGroups struct {
	groups   []string
	expiresAt time.Time
}

const cacheTTL = 1 * time.Minute

// JWKS cache for Cognito public keys
var (
	jwksCache = struct {
		sync.RWMutex
		keys   map[string]*rsa.PublicKey
		expiry time.Time
	}{
		keys: make(map[string]*rsa.PublicKey),
	}
	jwksCacheTTL = 1 * time.Hour
)

// PermissionConfig maps permission names to groups that grant them
type PermissionConfig struct {
	Permissions map[string][]string
}

var (
	permissionConfig     *PermissionConfig
	permissionConfigOnce sync.Once
)

// initPermissionConfig loads permission configuration from environment variables.
// Default: view = viewers, editors, admins; write = editors, admins.
func initPermissionConfig() {
	permissionConfigOnce.Do(func() {
		config := &PermissionConfig{
			Permissions: make(map[string][]string),
		}

		jsonConfig := os.Getenv("PERMISSION_GROUPS")
		if jsonConfig != "" {
			if err := json.Unmarshal([]byte(jsonConfig), &config.Permissions); err == nil {
				log.Printf("Loaded permission config from PERMISSION_GROUPS: %+v", config.Permissions)
				permissionConfig = config
				return
			}
			log.Printf("Failed to parse PERMISSION_GROUPS JSON, trying individual env vars")
		}

		envPrefix := "PERMISSION_"
		for _, env := range os.Environ() {
			if !strings.HasPrefix(env, envPrefix) {
				continue
			}
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			value := parts[1]
			permissionName := strings.TrimPrefix(key, envPrefix)
			permissionName = strings.TrimSuffix(permissionName, "_GROUPS")
			permissionName = strings.ToLower(permissionName)
			if permissionName == "" {
				continue
			}
			groups := strings.Split(value, ",")
			trimmedGroups := make([]string, 0, len(groups))
			for _, g := range groups {
				g = strings.TrimSpace(g)
				if g != "" {
					trimmedGroups = append(trimmedGroups, g)
				}
			}
			if len(trimmedGroups) > 0 {
				config.Permissions[permissionName] = trimmedGroups
			}
		}

		if len(config.Permissions) == 0 {
			config.Permissions = map[string][]string{
				"view":  {"viewers", "editors", "admins"},
				"write": {"editors", "admins"},
			}
			log.Printf("Using default permission config: %+v", config.Permissions)
		} else {
			log.Printf("Loaded permission config from environment: %+v", config.Permissions)
		}
		permissionConfig = config
	})
}

func hasPermission(groups []string, permission string) bool {
	initPermissionConfig()
	if permissionConfig == nil {
		return false
	}
	permissionGroups, ok := permissionConfig.Permissions[strings.ToLower(permission)]
	if !ok {
		return false
	}
	for _, userGroup := range groups {
		for _, permGroup := range permissionGroups {
			if userGroup == permGroup {
				return true
			}
		}
	}
	return false
}

func calculatePermissions(groups []string) map[string]bool {
	initPermissionConfig()
	permissions := make(map[string]bool)
	if permissionConfig == nil {
		return permissions
	}
	for permission := range permissionConfig.Permissions {
		permissions[permission] = hasPermission(groups, permission)
	}
	return permissions
}

func initCognitoClient() {
	cognitoClientOnce.Do(func() {
		userPoolID = os.Getenv("COGNITO_USER_POOL_ID")
		if userPoolID == "" {
			log.Printf("COGNITO_USER_POOL_ID not set - group queries will be disabled")
			return
		}
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if region == "" {
			parts := strings.Split(userPoolID, "_")
			if len(parts) > 0 {
				region = parts[0]
			}
		}
		if region == "" {
			log.Printf("AWS region not found - group queries will be disabled")
			return
		}
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		if err != nil {
			log.Printf("Failed to load AWS config: %v - group queries will be disabled", err)
			return
		}
		cognitoClient = cognitoidentityprovider.NewFromConfig(cfg)
		log.Printf("Cognito client initialized for user pool: %s (region: %s)", userPoolID, region)
	})
}

func invalidateGroupCache(userSub string) {
	groupCache.Lock()
	delete(groupCache.data, userSub)
	groupCache.Unlock()
}

func getGroupsFromCognito(ctx context.Context, userSub string, forceRefresh bool) ([]string, error) {
	initCognitoClient()
	if cognitoClient == nil || userPoolID == "" {
		return nil, nil
	}
	if !forceRefresh {
		groupCache.RLock()
		if cached, ok := groupCache.data[userSub]; ok {
			if time.Now().Before(cached.expiresAt) {
				groupCache.RUnlock()
				debugLog("Using cached groups for user %s: %v", userSub, cached.groups)
				return cached.groups, nil
			}
		}
		groupCache.RUnlock()
	} else {
		invalidateGroupCache(userSub)
	}

	result, err := cognitoClient.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(userSub),
	})
	if err != nil {
		log.Printf("Failed to query Cognito groups for user %s: %v", userSub, err)
		return nil, err
	}
	groups := make([]string, 0, len(result.Groups))
	for _, group := range result.Groups {
		if group.GroupName != nil {
			groups = append(groups, *group.GroupName)
		}
	}
	groupCache.Lock()
	groupCache.data[userSub] = cachedGroups{groups: groups, expiresAt: time.Now().Add(cacheTTL)}
	groupCache.Unlock()
	return groups, nil
}

// User represents an authenticated user with Cognito attributes
type User struct {
	Sub         string
	Email       string
	Groups      []string
	Permissions map[string]bool
}

// CognitoClaims represents the JWT claims from AWS Cognito (via ALB)
type CognitoClaims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	CognitoGroups []string `json:"cognito:groups"`
	Exp           int64    `json:"exp"`
	Iss           string   `json:"iss"`
}

type contextKey string

const userContextKey contextKey = "user"

// Middleware extracts and validates the Cognito JWT from ALB headers or Authorization Bearer.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string
		var fromALB bool

		tokenStr = r.Header.Get("x-amzn-oidc-data")
		if tokenStr != "" {
			fromALB = true
		}
		if tokenStr == "" {
			tokenStr = r.Header.Get("x-amzn-oidc-accesstoken")
			if tokenStr != "" {
				fromALB = true
			}
		}
		if tokenStr == "" {
			tokenStr = r.Header.Get("x-amzn-oidc-identity")
			if tokenStr != "" {
				fromALB = true
			}
		}
		if tokenStr == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				tokenStr = strings.TrimSpace(authHeader[7:])
				fromALB = false
			}
		}

		if tokenStr == "" {
			log.Printf("Missing JWT token in request headers")
			http.Error(w, "Unauthorized: missing authentication token", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			log.Printf("Invalid JWT format: expected 3 parts, got %d", len(parts))
			http.Error(w, "Unauthorized: invalid token format", http.StatusUnauthorized)
			return
		}

		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		}
		if err != nil {
			payloadBytes, err = base64.StdEncoding.DecodeString(parts[1])
		}
		if err != nil {
			log.Printf("Failed to decode JWT payload: %v", err)
			http.Error(w, "Unauthorized: invalid token encoding", http.StatusUnauthorized)
			return
		}

		var claims CognitoClaims
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			log.Printf("Failed to parse JWT claims: %v", err)
			http.Error(w, "Unauthorized: invalid token claims", http.StatusUnauthorized)
			return
		}
		rawClaims := map[string]interface{}{}
		_ = json.Unmarshal(payloadBytes, &rawClaims)
		debugLog("JWT claims: %+v", rawClaims)

		if !fromALB {
			if claims.Iss == "" {
				if issRaw, ok := rawClaims["iss"]; ok {
					if issStr, ok := issRaw.(string); ok {
						claims.Iss = issStr
					}
				}
			}
			if claims.Iss == "" {
				http.Error(w, "Unauthorized: missing token issuer", http.StatusUnauthorized)
				return
			}
			if err := verifyJWTSignature(tokenStr, claims.Iss); err != nil {
				log.Printf("JWT signature verification failed: %v", err)
				http.Error(w, "Unauthorized: invalid token signature", http.StatusUnauthorized)
				return
			}
			if err := verifyIssuer(claims.Iss); err != nil {
				log.Printf("Issuer verification failed: %v", err)
				http.Error(w, "Unauthorized: invalid token issuer", http.StatusUnauthorized)
				return
			}
		}

		if claims.Exp > 0 {
			if time.Now().Unix() > claims.Exp {
				http.Error(w, "Unauthorized: token expired", http.StatusUnauthorized)
				return
			}
		} else if expRaw, ok := rawClaims["exp"]; ok {
			if expFloat, ok := expRaw.(float64); ok {
				if time.Now().Unix() > int64(expFloat) {
					http.Error(w, "Unauthorized: token expired", http.StatusUnauthorized)
					return
				}
			}
		}

		var finalGroups []string
		if len(claims.CognitoGroups) > 0 {
			finalGroups = append(finalGroups, claims.CognitoGroups...)
		} else if groupsRaw, ok := rawClaims["cognito:groups"]; ok {
			if groupsSlice, ok := groupsRaw.([]interface{}); ok {
				for _, g := range groupsSlice {
					if groupStr, ok := g.(string); ok {
						finalGroups = append(finalGroups, groupStr)
					}
				}
			}
		}

		cognitoGroups, err := getGroupsFromCognito(r.Context(), claims.Sub, false)
		if err == nil {
			finalGroups = cognitoGroups
		} else if len(finalGroups) == 0 {
			log.Printf("No groups available from Cognito or token: %v", err)
		}

		permissions := calculatePermissions(finalGroups)
		hasAnyPermission := false
		for _, granted := range permissions {
			if granted {
				hasAnyPermission = true
				break
			}
		}
		allowedWithoutPermissions := r.URL.Path == "/forbidden" || r.URL.Path == "/whoami"
		if !allowedWithoutPermissions && (len(finalGroups) == 0 || !hasAnyPermission) {
			log.Printf("User %s has no groups or permissions - redirecting to forbidden", claims.Email)
			http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
			return
		}

		user := User{
			Sub:         claims.Sub,
			Email:       claims.Email,
			Groups:      finalGroups,
			Permissions: permissions,
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext returns the authenticated user from the request context
func UserFromContext(ctx context.Context) User {
	user, ok := ctx.Value(userContextKey).(User)
	if !ok {
		return User{}
	}
	return user
}

// RequirePermission restricts access to handlers that need a specific permission.
// For "write" (and create_request/approve), it forces a fresh Cognito group fetch.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			isWriteOperation := permission == "write" || permission == "create_request" || permission == "approve"

			if isWriteOperation {
				groups, err := getGroupsFromCognito(r.Context(), user.Sub, true)
				if err != nil {
					log.Printf("Failed to refresh groups for write operation: %v - denying access", err)
					http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
					return
				}
				if len(groups) == 0 {
					log.Printf("User %s has no groups - denying write operation %s", user.Email, permission)
					http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
					return
				}
				user.Groups = groups
				user.Permissions = calculatePermissions(groups)
				ctx := context.WithValue(r.Context(), userContextKey, user)
				r = r.WithContext(ctx)
			}

			if !user.HasPermission(permission) {
				log.Printf("User %s denied access to %s", user.Email, permission)
				http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HasPermission returns whether the user has the given permission
func (u User) HasPermission(permission string) bool {
	if u.Permissions == nil {
		return false
	}
	return u.Permissions[strings.ToLower(permission)]
}

func verifyIssuer(iss string) error {
	if iss == "" {
		return fmt.Errorf("issuer claim is empty")
	}
	initCognitoClient()
	if userPoolID == "" {
		return nil
	}
	parts := strings.Split(userPoolID, "_")
	if len(parts) < 2 {
		return fmt.Errorf("invalid user pool ID format")
	}
	region := parts[0]
	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)
	if iss != expectedIssuer {
		return fmt.Errorf("issuer mismatch: expected %s, got %s", expectedIssuer, iss)
	}
	return nil
}

func verifyJWTSignature(tokenStr, issuer string) error {
	if issuer == "" {
		return fmt.Errorf("issuer is required for signature verification")
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return fmt.Errorf("missing kid in JWT header")
	}
	publicKey, err := getPublicKey(issuer, kid)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	parser := jwt.NewParser()
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return fmt.Errorf("failed to parse/verify token: %w", err)
	}
	if !token.Valid {
		return fmt.Errorf("token is not valid")
	}
	return nil
}

func getPublicKey(issuer, kid string) (*rsa.PublicKey, error) {
	jwksCache.RLock()
	if time.Now().Before(jwksCache.expiry) {
		if key, ok := jwksCache.keys[kid]; ok {
			jwksCache.RUnlock()
			return key, nil
		}
	}
	jwksCache.RUnlock()

	jwksURL := fmt.Sprintf("%s/.well-known/jwks.json", issuer)
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	jwksCache.Lock()
	defer jwksCache.Unlock()
	jwksCache.keys = make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}
		var eInt int
		for i := 0; i < len(eBytes); i++ {
			eInt = eInt<<8 | int(eBytes[i])
		}
		if eInt == 0 {
			eInt = 65537
		}
		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}
		if publicKey.N.Sign() <= 0 || publicKey.E <= 0 {
			continue
		}
		jwksCache.keys[key.Kid] = publicKey
	}
	jwksCache.expiry = time.Now().Add(jwksCacheTTL)
	if key, ok := jwksCache.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}
