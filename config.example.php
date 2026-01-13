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

// Logging (optional)
define('ENABLE_ERROR_LOGGING', true);
define('LOG_FILE', __DIR__ . '/logs/auth.log');

// Optional: Rate limiting
define('ENABLE_RATE_LIMITING', false);
define('MAX_REQUESTS_PER_IP', 10); // per minute

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
 * Check if a domain is allowed for authentication
 * Domains are now managed through the dashboard by whitelisted users
 * See database table: user_allowed_domains
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
 * Check if user is whitelisted for dashboard access
 * Users are now managed by their Twitch ID (not username)
 */
function isWhitelistedUser($twitchId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
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
    $stmt = $conn->prepare(
        "INSERT INTO auth_logs (service, origin_domain, user_id, user_login, user_display_name, user_email, requested_scopes, success, error_message, ip_address, user_agent) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param(
        "sssssssssss",
        $service,
        $originDomain,
        $userId,
        $userLogin,
        $userDisplayName,
        $userEmail,
        $requestedScopes,
        $success,
        $errorMessage,
        $ipAddress,
        $userAgent
    );
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}
?>