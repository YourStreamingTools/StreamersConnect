<?php
/**
 * StreamersConnect Configuration Example
 * 
 * Copy this structure to your server's config directory and fill in your credentials.
 */

// Your StreamersConnect domain
define('STREAMERS_CONNECT_DOMAIN', 'streamersconnect.com');
define('REDIRECT_URI', 'https://' . STREAMERS_CONNECT_DOMAIN . '/callback.php');
define('INTERNAL_DASHBOARD_URL', 'https://' . STREAMERS_CONNECT_DOMAIN . '/dashboard.php');

// Security settings
define('SESSION_LIFETIME', 3600); // 1 hour
define('USE_SECURE_COOKIES', true); // Set to true in production (requires HTTPS)
// Auth data signing key (HMAC-SHA256). Replace with a strong random value in production.
// If empty, signed tokens won't be generated.
define('AUTH_DATA_SIGNING_KEY', 'replace_with_strong_random');
// Whether return_url host can be a subdomain of the provided login domain (default: false).
// If true, return_url like "sub.example.com" will be allowed when origin login is "example.com".
define('ALLOW_RETURN_URL_SUBDOMAINS', false);

// Logging (optional)
define('ENABLE_ERROR_LOGGING', true);
define('LOG_FILE', __DIR__ . '/logs/auth.log');

// Optional: Rate limiting
define('ENABLE_RATE_LIMITING', false);
define('MAX_REQUESTS_PER_IP', 10); // per minute

// Server-side short-lived token TTL (seconds) used for token-exchange flow
// Default: 300 (5 minutes)
define('SERVER_TOKEN_TTL', 300); // seconds

// Log path for automated cleanup script output
define('CLEANUP_TOKENS_LOG_PATH', '/var/log/streamersconnect/cleanup_tokens.log');

// Database Configuration
define('STREAMERSCONNECT_DB_HOST', 'your_db_host_here'); // Usually 'localhost'
define('STREAMERSCONNECT_DB_USER', 'your_db_user_here');
define('STREAMERSCONNECT_DB_PASS', 'your_db_password_here');
define('STREAMERSCONNECT_DB_NAME', 'streamersconnect');

/**
 * Get database connection for StreamersConnect
 */
function getStreamersConnectDB() {
    static $conn = null;
    if ($conn === null) {
        try {
            $conn = new mysqli(
                STREAMERSCONNECT_DB_HOST,
                STREAMERSCONNECT_DB_USER,
                STREAMERSCONNECT_DB_PASS,
                STREAMERSCONNECT_DB_NAME
            );
            if ($conn->connect_error) {
                error_log('StreamersConnect DB Connection failed: ' . $conn->connect_error);
                return false;
            }
            $conn->set_charset('utf8mb4');
        } catch (Exception $e) {
            error_log('StreamersConnect DB Exception: ' . $e->getMessage());
            return false;
        }
    }
    return $conn;
}

/**
 * Get default OAuth credentials for a service from database
 */
function getDefaultOAuthCredentials($service, $twitchId = null) {
    $conn = getStreamersConnectDB();
    if ($conn && $twitchId) {
        // Get user's default OAuth app
        $stmt = $conn->prepare("SELECT client_id, client_secret FROM oauth_applications WHERE user_login IN (SELECT user_login FROM dashboard_whitelist WHERE twitch_id = ?) AND service = ? AND is_default = 1 LIMIT 1");
        $stmt->bind_param("ss", $twitchId, $service);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($row = $result->fetch_assoc()) {
            $stmt->close();
            return [
                'client_id' => $row['client_id'],
                'client_secret' => $row['client_secret']
            ];
        }
        $stmt->close();
    }
    return false;
}

/**
 * Get OAuth credentials for a specific domain
 * Checks if the domain has a custom OAuth app assigned, otherwise gets owner's default
 */
function getOAuthCredentialsForDomain($service, $domain) {
    $conn = getStreamersConnectDB();
    if (!$conn) return null;
    // First try: Look up domain and its assigned OAuth app
    $stmt = $conn->prepare("
        SELECT oa.client_id, oa.client_secret 
        FROM user_allowed_domains uad
        INNER JOIN oauth_applications oa ON uad.oauth_app_id = oa.id
        WHERE uad.domain = ? AND oa.service = ?
    ");
    $stmt->bind_param('ss', $domain, $service);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stmt->close();
        return [
            'client_id' => $row['client_id'],
            'client_secret' => $row['client_secret']
        ];
    }
    $stmt->close();
    // Second try: Get domain owner's default OAuth app
    $stmt = $conn->prepare("
        SELECT oa.client_id, oa.client_secret
        FROM user_allowed_domains uad
        INNER JOIN dashboard_whitelist dw ON uad.twitch_id = dw.twitch_id
        INNER JOIN oauth_applications oa ON dw.user_login = oa.user_login
        WHERE uad.domain = ? AND oa.service = ? AND oa.is_default = 1
        LIMIT 1
    ");
    $stmt->bind_param('ss', $domain, $service);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stmt->close();
        return [
            'client_id' => $row['client_id'],
            'client_secret' => $row['client_secret']
        ];
    }
    $stmt->close();
    return null;
}

/**
 * Check if a domain is allowed for authentication
 */
function isAllowedDomain($domain) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("SELECT id FROM user_allowed_domains WHERE domain = ? LIMIT 1");
    $stmt->bind_param("s", $domain);
    $stmt->execute();
    $result = $stmt->get_result();
    $isAllowed = $result->num_rows > 0;
    $stmt->close();
    return $isAllowed;
}

/**
 * Get all domains for a user
 */
function getUserDomains($twitchId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return [];
    $stmt = $conn->prepare("SELECT id, domain, notes, created_at FROM user_allowed_domains WHERE twitch_id = ? ORDER BY domain ASC");
    $stmt->bind_param("s", $twitchId);
    $stmt->execute();
    $result = $stmt->get_result();
    $domains = [];
    while ($row = $result->fetch_assoc()) {
        $domains[] = $row;
    }
    $stmt->close();
    return $domains;
}

/**
 * Utilities: base64url encode / decode
 */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}

// Signing key storage & rotation helpers
// NOTE: Requires migration: StreamersConnect/sql/2026-02-03-add-auth-signing-keys.sql
function get_active_signing_key() {
    // Try DB first
    $conn = getStreamersConnectDB();
    if ($conn) {
        $stmt = $conn->prepare("SELECT kid, key_value, is_active, expires_at FROM auth_signing_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1");
        if ($stmt) {
            $stmt->execute();
            $res = $stmt->get_result();
            if ($row = $res->fetch_assoc()) {
                $stmt->close();
                return ['kid' => $row['kid'], 'key' => $row['key_value'], 'expires_at' => $row['expires_at']];
            }
            $stmt->close();
        }
    }
    // Fallback to config-defined key
    if (defined('AUTH_DATA_SIGNING_KEY') && AUTH_DATA_SIGNING_KEY) {
        return ['kid' => 'cfg', 'key' => AUTH_DATA_SIGNING_KEY, 'expires_at' => null];
    }
    return null;
}

function get_signing_key_by_kid($kid) {
    if (!$kid) return null;
    if ($kid === 'cfg' && defined('AUTH_DATA_SIGNING_KEY') && AUTH_DATA_SIGNING_KEY) {
        return ['kid' => 'cfg', 'key' => AUTH_DATA_SIGNING_KEY];
    }
    $conn = getStreamersConnectDB();
    if (!$conn) return null;
    $stmt = $conn->prepare("SELECT kid, key_value, is_active, expires_at FROM auth_signing_keys WHERE kid = ? LIMIT 1");
    $stmt->bind_param('s', $kid);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($row = $res->fetch_assoc()) {
        $stmt->close();
        return ['kid' => $row['kid'], 'key' => $row['key_value'], 'is_active' => $row['is_active'], 'expires_at' => $row['expires_at']];
    }
    $stmt->close();
    return null;
}

function create_signing_key($keyValue, $activate = false, $expiresAt = null) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $kid = bin2hex(random_bytes(8));
    $createdAt = date('Y-m-d H:i:s');
    $stmt = $conn->prepare("INSERT INTO auth_signing_keys (kid, key_value, is_active, created_at, expires_at) VALUES (?, ?, ?, ?, ?)");
    $isActive = $activate ? 1 : 0;
    $stmt->bind_param('ssiss', $kid, $keyValue, $isActive, $createdAt, $expiresAt);
    $result = $stmt->execute();
    $stmt->close();
    if ($activate) {
        // Deactivate other keys
        $stmt = $conn->prepare("UPDATE auth_signing_keys SET is_active = 0 WHERE kid <> ?");
        $stmt->bind_param('s', $kid);
        $stmt->execute();
        $stmt->close();
    }
    return $result ? $kid : false;
}

function activate_signing_key($kid) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("UPDATE auth_signing_keys SET is_active = 0");
    $stmt->execute();
    $stmt->close();
    $stmt = $conn->prepare("UPDATE auth_signing_keys SET is_active = 1 WHERE kid = ?");
    $stmt->bind_param('s', $kid);
    $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();
    return $affected > 0;
}

/**
 * Create a signed auth data token (versioned) using HMAC-SHA256 and key id.
 * New format: v1.<kid>.<base64url(payload)>.<base64url(hmac)>
 * Legacy (no kid) format v1.<payload>.<sig> is still accepted for backward compatibility.
 */
function create_signed_auth_data($data, $kid = null) {
    // Determine key to use
    $keyData = null;
    if ($kid) {
        $keyData = get_signing_key_by_kid($kid);
        if (!$keyData) return null;
    } else {
        $keyData = get_active_signing_key();
    }
    if (!$keyData || empty($keyData['key'])) return null;
    $payload = base64url_encode(json_encode($data));
    $signature = hash_hmac('sha256', $payload, $keyData['key'], true);
    $sig = base64url_encode($signature);
    // If key came from config (kid cfg), reflect that
    $kidPart = $keyData['kid'] ?? 'cfg';
    return 'v1.' . $kidPart . '.' . $payload . '.' . $sig;
}

/**
 * Verify a signed auth data token. Supports v1.<kid>.<payload>.<sig> and legacy v1.<payload>.<sig>.
 * Returns payload array on success or false on failure.
 */
function verify_signed_auth_data($signed) {
    if (!is_string($signed) || strpos($signed, 'v1.') !== 0) return false;
    $parts = explode('.', $signed);
    if (count($parts) === 4) {
        list($v, $kid, $payload, $sig) = $parts;
        $keyData = get_signing_key_by_kid($kid);
        if (!$keyData || empty($keyData['key'])) return false;
        $expected = base64url_encode(hash_hmac('sha256', $payload, $keyData['key'], true));
        if (!hash_equals($expected, $sig)) return false;
        $json = base64url_decode($payload);
        return json_decode($json, true);
    } elseif (count($parts) === 3) {
        // Legacy: try config key first, then any active DB key
        list($v, $payload, $sig) = $parts;
        // Try config
        if (defined('AUTH_DATA_SIGNING_KEY') && AUTH_DATA_SIGNING_KEY) {
            $expected = base64url_encode(hash_hmac('sha256', $payload, AUTH_DATA_SIGNING_KEY, true));
            if (hash_equals($expected, $sig)) {
                $json = base64url_decode($payload);
                return json_decode($json, true);
            }
        }
        // Try active DB key(s)
        $conn = getStreamersConnectDB();
        if ($conn) {
            $stmt = $conn->prepare("SELECT key_value FROM auth_signing_keys WHERE expires_at IS NULL OR expires_at >= NOW()");
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $expected = base64url_encode(hash_hmac('sha256', $payload, $row['key_value'], true));
                if (hash_equals($expected, $sig)) {
                    $stmt->close();
                    $json = base64url_decode($payload);
                    return json_decode($json, true);
                }
            }
            $stmt->close();
        }
        return false;
    }
    return false;
}

/**
 * Validate whether a given return URL is acceptable for the origin/login domain.
 * By default this requires exact host equality, but can be configured to allow
 * subdomains using ALLOW_RETURN_URL_SUBDOMAINS in config.
 */
function is_valid_return_url_for_origin($returnUrl, $originDomain) {
    $host = parse_url($returnUrl, PHP_URL_HOST);
    if (!$host) return false;
    $host = strtolower($host);
    $originDomain = strtolower($originDomain);
    if ($host === $originDomain) return true;
    if (defined('ALLOW_RETURN_URL_SUBDOMAINS') && ALLOW_RETURN_URL_SUBDOMAINS) {
        return (substr($host, -strlen('.' . $originDomain)) === '.' . $originDomain);
    }
    return false;
}

/**
 * Check if user is whitelisted for dashboard access
 */
function isWhitelistedUser($twitchId) {
    $conn = getStreamersConnectDB();
    if (!$conn) {
        error_log("isWhitelistedUser: Database connection failed");
        return false;
    }
    $stmt = $conn->prepare("SELECT id FROM dashboard_whitelist WHERE twitch_id = ?");
    $stmt->bind_param("s", $twitchId);
    $stmt->execute();
    $result = $stmt->get_result();
    $isWhitelisted = $result->num_rows > 0;
    $stmt->close();
    return $isWhitelisted;
}

/**
 * Log authentication attempt
 */
function logAuthAttempt($service, $originDomain, $userData, $requestedScopes, $success, $errorMessage = null) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $userId = $userData['id'] ?? null;
    $userLogin = $userData['login'] ?? null;
    $userDisplayName = $userData['display_name'] ?? null;
    $userEmail = $userData['email'] ?? null;
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    // Coerce success to integer (DB expects tinyint / int)
    $successInt = $success ? 1 : 0;
    $stmt = $conn->prepare(
        "INSERT INTO auth_logs (service, origin_domain, user_id, user_login, user_display_name, user_email, requested_scopes, success, error_message, ip_address, user_agent) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    // Types: 7 strings, 1 integer, 3 strings
    $stmt->bind_param(
        "sssssssisss",
        $service,
        $originDomain,
        $userId,
        $userLogin,
        $userDisplayName,
        $userEmail,
        $requestedScopes,
        $successInt,
        $errorMessage,
        $ipAddress,
        $userAgent
    );
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}
?>