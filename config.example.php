<?php
/**
 * StreamersConnect Configuration Example
 *
 * Copy this file to your server's config directory, rename it (e.g. streamersconnect.php),
 * fill in your real values, and point the require_once in each PHP file to that path.
 *
 * All functions in this file are production-ready — do not modify them, only the constants above.
 */

// Domain 
define('STREAMERS_CONNECT_DOMAIN', ''); // e.g. 'auth.example.com' — the domain where StreamersConnect is hosted. Must be HTTPS in production.
define('REDIRECT_URI',             'https://' . STREAMERS_CONNECT_DOMAIN . '/callback.php');
define('INTERNAL_DASHBOARD_URL',   'https://' . STREAMERS_CONNECT_DOMAIN . '/dashboard.php');

// Security─
define('SESSION_LIFETIME',    3600); // seconds
define('USE_SECURE_COOKIES',  true); // requires HTTPS in production

// HMAC-SHA256 key used to sign auth_data tokens. Set a strong random value in production.
// If left empty, signed tokens will not be generated.
define('AUTH_DATA_SIGNING_KEY', 'replace_with_a_strong_random_secret');

// Set to true to allow return_url hosts that are subdomains of the login domain.
// e.g. return_url "sub.example.com" accepted when login domain is "example.com".
define('ALLOW_RETURN_URL_SUBDOMAINS', false);

// Logging 
define('ENABLE_ERROR_LOGGING',      true);
define('CLEANUP_TOKENS_LOG_PATH',   '/var/log/'. STREAMERS_CONNECT_DOMAIN . '/cleanup_tokens.log');
define('LOG_FILE',                  '/var/log/'. STREAMERS_CONNECT_DOMAIN . '/auth.log');

// Rate limiting (optional)
define('ENABLE_RATE_LIMITING',  false);
define('MAX_REQUESTS_PER_IP',   10); // per minute

// Token TTL
// Lifetime (seconds) of short-lived server-side tokens used in the token-exchange flow.
define('SERVER_TOKEN_TTL', 300);

// Database
// Option A: hard-code credentials directly.
define('STREAMERSCONNECT_DB_HOST', 'localhost');
define('STREAMERSCONNECT_DB_USER', 'your_db_user_here');
define('STREAMERSCONNECT_DB_PASS', 'your_db_password_here');
define('STREAMERSCONNECT_DB_NAME', 'streamersconnect');

// Option B: pull credentials from a shared database config file (recommended).
// Comment out Option A above and uncomment the three lines below:
// require_once __DIR__ . '/database.php';
// define('STREAMERSCONNECT_DB_HOST', $db_servername);
// define('STREAMERSCONNECT_DB_USER', $db_username);
// define('STREAMERSCONNECT_DB_PASS', $db_password);
// define('STREAMERSCONNECT_DB_NAME', 'streamersconnect');

// ═════════════════════════════════════════════════════════════════════════════
// Functions — do not edit below this line
// ═════════════════════════════════════════════════════════════════════════════

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

function getDefaultOAuthCredentials($service, $twitchId = null) {
    $conn = getStreamersConnectDB();
    if ($conn && $twitchId) {
        $stmt = $conn->prepare("SELECT client_id, client_secret FROM oauth_applications WHERE user_login IN (SELECT user_login FROM dashboard_whitelist WHERE twitch_id = ?) AND service = ? AND is_default = 1 LIMIT 1");
        $stmt->bind_param("ss", $twitchId, $service);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($row = $result->fetch_assoc()) {
            $stmt->close();
            return ['client_id' => $row['client_id'], 'client_secret' => $row['client_secret']];
        }
        $stmt->close();
    }
    return false;
}

/**
 * Returns the user_allowed_domains row whose pattern matches $domain.
 * Supports exact entries and wildcard entries (*.example.com), which match
 * any subdomain at any depth.
 */
function findAllowedDomainRow($domain) {
    $conn = getStreamersConnectDB();
    if (!$conn) return null;
    // Exact match
    $stmt = $conn->prepare("SELECT * FROM user_allowed_domains WHERE domain = ? LIMIT 1");
    $stmt->bind_param('s', $domain);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($row) return $row;
    // Wildcard match: *.example.com matches foo.example.com, bar.baz.example.com, etc.
    $stmt = $conn->prepare("SELECT * FROM user_allowed_domains WHERE domain LIKE '*.%'");
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $suffix = substr($row['domain'], 2); // strip '*.'
        if (str_ends_with($domain, '.' . $suffix)) {
            $stmt->close();
            return $row;
        }
    }
    $stmt->close();
    return null;
}

/**
 * Get OAuth credentials for a specific domain.
 * Checks for a custom OAuth app assigned to the domain first, then falls back
 * to the domain owner's default app. Supports wildcard domain entries.
 */
function getOAuthCredentialsForDomain($service, $domain) {
    $conn = getStreamersConnectDB();
    if (!$conn) return null;
    // 1. Exact match — domain with a custom OAuth app assigned
    $stmt = $conn->prepare("
        SELECT oa.id, oa.client_id, oa.client_secret
        FROM user_allowed_domains uad
        INNER JOIN oauth_applications oa ON uad.oauth_app_id = oa.id
        WHERE uad.domain = ? AND oa.service = ?
    ");
    $stmt->bind_param('ss', $domain, $service);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $stmt->close();
        return ['id' => $row['id'], 'client_id' => $row['client_id'], 'client_secret' => $row['client_secret']];
    }
    $stmt->close();
    // 2. Wildcard match — wildcard entry with a custom OAuth app assigned
    $stmt = $conn->prepare("
        SELECT oa.id, oa.client_id, oa.client_secret, uad.domain AS pattern
        FROM user_allowed_domains uad
        INNER JOIN oauth_applications oa ON uad.oauth_app_id = oa.id
        WHERE uad.domain LIKE '*.%' AND oa.service = ?
    ");
    $stmt->bind_param('s', $service);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $suffix = substr($row['pattern'], 2);
        if (str_ends_with($domain, '.' . $suffix)) {
            $stmt->close();
            return ['id' => $row['id'], 'client_id' => $row['client_id'], 'client_secret' => $row['client_secret']];
        }
    }
    $stmt->close();
    // 3. Exact match — domain owner's default OAuth app
    $stmt = $conn->prepare("
        SELECT oa.id, oa.client_id, oa.client_secret
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
        return ['id' => $row['id'], 'client_id' => $row['client_id'], 'client_secret' => $row['client_secret']];
    }
    $stmt->close();
    // 4. Wildcard match — wildcard entry owner's default OAuth app
    $stmt = $conn->prepare("
        SELECT oa.id, oa.client_id, oa.client_secret, uad.domain AS pattern
        FROM user_allowed_domains uad
        INNER JOIN dashboard_whitelist dw ON uad.twitch_id = dw.twitch_id
        INNER JOIN oauth_applications oa ON dw.user_login = oa.user_login
        WHERE uad.domain LIKE '*.%' AND oa.service = ? AND oa.is_default = 1
    ");
    $stmt->bind_param('s', $service);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $suffix = substr($row['pattern'], 2);
        if (str_ends_with($domain, '.' . $suffix)) {
            $stmt->close();
            return ['id' => $row['id'], 'client_id' => $row['client_id'], 'client_secret' => $row['client_secret']];
        }
    }
    $stmt->close();
    return null;
}

/**
 * Check if a domain is allowed for authentication.
 * Supports exact entries and wildcard entries (*.example.com).
 */
function isAllowedDomain($domain) {
    return findAllowedDomainRow($domain) !== null;
}

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

// Signing key helpers
// Requires migration: sql/2026-02-03-add-auth-signing-keys.sql

function get_active_signing_key() {
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

// API client helpers─

function create_api_client($name, $ownerTwitchId = null, $allowedOrigins = null, $activate = true) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $clientId  = bin2hex(random_bytes(8));
    $apiKey    = bin2hex(random_bytes(32));
    $createdAt = date('Y-m-d H:i:s');
    $isActive  = $activate ? 1 : 0;
    $stmt = $conn->prepare("INSERT INTO api_clients (client_id, api_key, name, owner_twitch_id, allowed_origins, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('sssssis', $clientId, $apiKey, $name, $ownerTwitchId, $allowedOrigins, $isActive, $createdAt);
    $result = $stmt->execute();
    $stmt->close();
    return $result ? ['client_id' => $clientId, 'api_key' => $apiKey] : false;
}

function get_api_client_by_key($apiKey) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("SELECT id, client_id, api_key, name, owner_twitch_id, allowed_origins, is_active, usage_count, last_used, created_at FROM api_clients WHERE api_key = ? LIMIT 1");
    $stmt->bind_param('s', $apiKey);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($row = $res->fetch_assoc()) { $stmt->close(); return $row; }
    $stmt->close();
    return false;
}

function get_api_client_by_owner($ownerTwitchId) {
    $clients = list_api_clients_by_owner($ownerTwitchId);
    return $clients ? $clients[0] : false;
}

function list_api_clients_by_owner($ownerTwitchId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return [];
    $stmt = $conn->prepare("SELECT id, client_id, name, owner_twitch_id, allowed_origins, is_active, usage_count, last_used, created_at, RIGHT(api_key, 6) AS api_key_suffix FROM api_clients WHERE owner_twitch_id = ? ORDER BY created_at DESC");
    $stmt->bind_param('s', $ownerTwitchId);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = [];
    while ($row = $res->fetch_assoc()) {
        $rows[] = $row;
    }
    $stmt->close();
    return $rows;
}

function get_api_client_by_client_id($clientId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("SELECT id, client_id, api_key, name, owner_twitch_id, allowed_origins, is_active, usage_count, last_used, created_at FROM api_clients WHERE client_id = ? LIMIT 1");
    $stmt->bind_param('s', $clientId);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($row = $res->fetch_assoc()) { $stmt->close(); return $row; }
    $stmt->close();
    return false;
}

function list_api_clients() {
    $conn = getStreamersConnectDB();
    if (!$conn) return [];
    $res  = $conn->query("SELECT id, client_id, name, owner_twitch_id, allowed_origins, is_active, usage_count, last_used, created_at FROM api_clients ORDER BY created_at DESC");
    $rows = [];
    while ($row = $res->fetch_assoc()) $rows[] = $row;
    return $rows;
}

function deactivate_api_client($clientId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("UPDATE api_clients SET is_active = 0 WHERE client_id = ?");
    $stmt->bind_param('s', $clientId);
    $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();
    return $affected > 0;
}

function rotate_api_client_key($clientId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $newKey = bin2hex(random_bytes(32));
    $stmt = $conn->prepare("UPDATE api_clients SET api_key = ? WHERE client_id = ?");
    $stmt->bind_param('ss', $newKey, $clientId);
    $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();
    return $affected > 0 ? $newKey : false;
}

function record_api_client_usage($clientId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("UPDATE api_clients SET usage_count = usage_count + 1, last_used = NOW() WHERE client_id = ?");
    $stmt->bind_param('s', $clientId);
    $stmt->execute();
    $stmt->close();
    return true;
}

function require_api_key_or_die() {
    $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? null;
    if (!$apiKey) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null);
        if ($authHeader && preg_match('/Bearer\s+(.*)/i', $authHeader, $m)) {
            $apiKey = $m[1];
        }
    }
    if (!$apiKey) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Missing API key']);
        exit;
    }
    $client = get_api_client_by_key($apiKey);
    if (!$client || intval($client['is_active']) !== 1) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Invalid or inactive API key']);
        exit;
    }
    @record_api_client_usage($client['client_id']);
    return $client;
}

// Signed auth data

/**
 * Create a signed token: v1.<kid>.<base64url(payload)>.<base64url(hmac)>
 */
function create_signed_auth_data($data, $kid = null) {
    $keyData = $kid ? get_signing_key_by_kid($kid) : get_active_signing_key();
    if (!$keyData || empty($keyData['key'])) return null;
    $payload   = base64url_encode(json_encode($data));
    $sig       = base64url_encode(hash_hmac('sha256', $payload, $keyData['key'], true));
    $kidPart   = $keyData['kid'] ?? 'cfg';
    return 'v1.' . $kidPart . '.' . $payload . '.' . $sig;
}

/**
 * Verify a signed token. Accepts v1.<kid>.<payload>.<sig> and legacy v1.<payload>.<sig>.
 * Returns the decoded payload array on success, or false on failure.
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
        return json_decode(base64url_decode($payload), true);
    } elseif (count($parts) === 3) {
        // Legacy format — try config key first, then any non-expired DB key
        list($v, $payload, $sig) = $parts;
        if (defined('AUTH_DATA_SIGNING_KEY') && AUTH_DATA_SIGNING_KEY) {
            $expected = base64url_encode(hash_hmac('sha256', $payload, AUTH_DATA_SIGNING_KEY, true));
            if (hash_equals($expected, $sig)) return json_decode(base64url_decode($payload), true);
        }
        $conn = getStreamersConnectDB();
        if ($conn) {
            $stmt = $conn->prepare("SELECT key_value FROM auth_signing_keys WHERE expires_at IS NULL OR expires_at >= NOW()");
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $expected = base64url_encode(hash_hmac('sha256', $payload, $row['key_value'], true));
                if (hash_equals($expected, $sig)) {
                    $stmt->close();
                    return json_decode(base64url_decode($payload), true);
                }
            }
            $stmt->close();
        }
        return false;
    }
    return false;
}

// Return URL validation─

function is_valid_return_url_for_origin($returnUrl, $originDomain) {
    $host = parse_url($returnUrl, PHP_URL_HOST);
    if (!$host) return false;
    $host         = strtolower($host);
    $originDomain = strtolower($originDomain);
    if ($host === $originDomain) return true;
    if (defined('ALLOW_RETURN_URL_SUBDOMAINS') && ALLOW_RETURN_URL_SUBDOMAINS) {
        return str_ends_with($host, '.' . $originDomain);
    }
    return false;
}

// Webhook dispatch 

function dispatch_webhooks($service, $originDomain, $userData, $eventType) {
    $conn = getStreamersConnectDB();
    if (!$conn) return;
    // Resolve the domain owner — supports both exact and wildcard entries
    $domainRow = findAllowedDomainRow($originDomain);
    if (!$domainRow) return;
    $twitchId = $domainRow['twitch_id'];
    $eventCol = ($eventType === 'authentication_success') ? 'event_success' : 'event_failure';
    $stmt = $conn->prepare("SELECT webhook_url, secret, is_discord FROM webhooks WHERE twitch_id = ? AND {$eventCol} = 1");
    $stmt->bind_param('s', $twitchId);
    $stmt->execute();
    $res   = $stmt->get_result();
    $hooks = [];
    while ($hook = $res->fetch_assoc()) $hooks[] = $hook;
    $stmt->close();
    if (empty($hooks)) return;
    $timestamp = gmdate('Y-m-d\TH:i:s\Z');
    foreach ($hooks as $hook) {
        $url        = $hook['webhook_url'];
        $secret     = $hook['secret'];
        $useDiscord = intval($hook['is_discord']) === 1 || _sc_is_discord_webhook_url($url);
        if ($useDiscord) {
            $payload = _sc_build_discord_embed($service, $originDomain, $userData, $eventType, $timestamp);
            _sc_send_webhook($url, $payload, null);
        } else {
            $payload = json_encode([
                'event'     => $eventType,
                'timestamp' => $timestamp,
                'service'   => $service,
                'domain'    => $originDomain,
                'user'      => [
                    'id'           => $userData['id']           ?? null,
                    'login'        => $userData['login']        ?? null,
                    'display_name' => $userData['display_name'] ?? null,
                ],
            ]);
            _sc_send_webhook($url, $payload, hash_hmac('sha256', $payload, $secret));
        }
    }
}

function _sc_is_discord_webhook_url($url) {
    $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
    return ($host === 'discord.com' || $host === 'discordapp.com');
}

function _sc_build_discord_embed($service, $domain, $userData, $eventType, $timestamp) {
    $isSuccess = ($eventType === 'authentication_success');
    $fields    = [
        ['name' => 'Service', 'value' => ucfirst($service), 'inline' => true],
        ['name' => 'Domain',  'value' => $domain,           'inline' => true],
    ];
    if (!empty($userData['display_name'])) {
        $fields[] = ['name' => 'User', 'value' => $userData['display_name'], 'inline' => true];
    }
    return json_encode([
        'username' => 'StreamersConnect',
        'embeds'   => [[
            'title'     => $isSuccess ? 'Authentication Successful' : 'Authentication Failed',
            'color'     => $isSuccess ? 5763719 : 15548997,
            'fields'    => $fields,
            'timestamp' => $timestamp,
            'footer'    => ['text' => 'StreamersConnect Auth Notifications'],
        ]],
    ]);
}

function _sc_send_webhook($url, $jsonPayload, $signature) {
    $headers = ['Content-Type: application/json'];
    if ($signature !== null) {
        $headers[] = 'X-StreamersConnect-Signature: ' . $signature;
    }
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST,          true);
    curl_setopt($ch, CURLOPT_POSTFIELDS,    $jsonPayload);
    curl_setopt($ch, CURLOPT_HTTPHEADER,    $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,true);
    curl_setopt($ch, CURLOPT_TIMEOUT,       5);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode < 200 || $httpCode >= 300) {
        error_log("dispatch_webhooks: delivery to {$url} returned HTTP {$httpCode}: " . substr($response, 0, 200));
    }
}

// Server-side token exchange

function create_server_token($payloadArray, $originDomain = null, $ttl = null) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $ttl         = $ttl ?? (defined('SERVER_TOKEN_TTL') ? SERVER_TOKEN_TTL : 300);
    $token       = bin2hex(random_bytes(32));
    $payloadJson = json_encode($payloadArray);
    $createdAt   = date('Y-m-d H:i:s');
    $expiresAt   = date('Y-m-d H:i:s', time() + $ttl);
    $stmt = $conn->prepare("INSERT INTO auth_tokens (token, payload, origin_domain, created_at, expires_at, consumed) VALUES (?, ?, ?, ?, ?, 0)");
    $stmt->bind_param('sssss', $token, $payloadJson, $originDomain, $createdAt, $expiresAt);
    $result = $stmt->execute();
    $stmt->close();
    return $result ? $token : false;
}

function fetch_server_token($token) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("SELECT token, payload, origin_domain, created_at, expires_at, consumed FROM auth_tokens WHERE token = ? LIMIT 1");
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($row = $res->fetch_assoc()) { $stmt->close(); return $row; }
    $stmt->close();
    return false;
}

function consume_server_token($token) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("UPDATE auth_tokens SET consumed = 1 WHERE token = ? AND consumed = 0 AND expires_at >= NOW()");
    $stmt->bind_param('s', $token);
    $result  = $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();
    return ($result && $affected > 0);
}

// Dashboard access 

function isWhitelistedUser($twitchId) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $stmt = $conn->prepare("SELECT id FROM dashboard_whitelist WHERE twitch_id = ?");
    $stmt->bind_param("s", $twitchId);
    $stmt->execute();
    $isWhitelisted = $stmt->get_result()->num_rows > 0;
    $stmt->close();
    return $isWhitelisted;
}

// Auth logging

function logAuthAttempt($service, $originDomain, $userData, $requestedScopes, $success, $errorMessage = null) {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $successInt = $success ? 1 : 0;
    $stmt = $conn->prepare(
        "INSERT INTO auth_logs (service, origin_domain, user_id, user_login, user_display_name, user_email, requested_scopes, success, error_message, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    $userId          = $userData['id']           ?? null;
    $userLogin       = $userData['login']        ?? null;
    $userDisplayName = $userData['display_name'] ?? null;
    $userEmail       = $userData['email']        ?? null;
    $ipAddress       = $_SERVER['REMOTE_ADDR']   ?? null;
    $userAgent       = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $stmt->bind_param(
        "sssssssisss",
        $service, $originDomain, $userId, $userLogin, $userDisplayName,
        $userEmail, $requestedScopes, $successInt, $errorMessage, $ipAddress, $userAgent
    );
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}
?>