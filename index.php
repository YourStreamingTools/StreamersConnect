<?php
session_start();

// Load configuration
require_once '/var/www/config/streamersconnect.php';

// Handle auth callback for internal login
if (isset($_GET['auth_data'])) {
    $authData = null;
    // Prefer signed payload if present and valid
    if (isset($_GET['auth_data_sig']) && function_exists('verify_signed_auth_data')) {
        $verified = verify_signed_auth_data($_GET['auth_data_sig']);
        if ($verified !== false) {
            $authData = $verified;
        }
    }
    // Fallback to legacy base64 encoded payload
    if (!$authData) {
        $authData = json_decode(base64_decode($_GET['auth_data']), true);
    }
    if (isset($authData['success']) && $authData['success'] && $authData['service'] === 'twitch') {
        // Store user session
        $_SESSION['user_id'] = $authData['user']['id'];
        $_SESSION['user_login'] = $authData['user']['login'];
        $_SESSION['user_display_name'] = $authData['user']['display_name'];
        $_SESSION['user_email'] = $authData['user']['email'];
        $_SESSION['access_token'] = $authData['access_token'];
        $_SESSION['refresh_token'] = $authData['refresh_token'];
        $_SESSION['auth_service'] = $authData['service'];
    }
    // Redirect to clean URL
    header('Location: https://streamersconnect.com/');
    exit;
}
// Handle error
if (isset($_GET['error'])) {
    // Could display error message here
    // For now, just continue to show the page
}
// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: https://streamersconnect.com/');
    exit;
}

/**
 * Main handler for incoming authentication requests
 */
if (isset($_GET['service']) && isset($_GET['login']) && isset($_GET['scopes'])) {
    // Get and validate parameters
    $service = strtolower(htmlspecialchars($_GET['service'], ENT_QUOTES, 'UTF-8'));
    $originDomain = htmlspecialchars($_GET['login'], ENT_QUOTES, 'UTF-8');
    // Set default Twitch scope if none provided
    $requestedScopes = isset($_GET['scopes']) && trim($_GET['scopes']) !== '' ? htmlspecialchars($_GET['scopes'], ENT_QUOTES, 'UTF-8') : null;
    if ($service === 'twitch' && (!$requestedScopes || $requestedScopes === '')) {
        $requestedScopes = 'user:read:email';
    }
    // Check for custom OAuth credentials in headers
    $customClientId = $_SERVER['HTTP_X_OAUTH_CLIENT_ID'] ?? null;
    $customClientSecret = $_SERVER['HTTP_X_OAUTH_CLIENT_SECRET'] ?? null;
    // If no custom credentials in headers, check for domain-specific OAuth app
    if (!$customClientId || !$customClientSecret) {
        $domainCredentials = getOAuthCredentialsForDomain($service, $originDomain);
        if ($domainCredentials) {
            $customClientId = $customClientId ?? $domainCredentials['client_id'];
            $customClientSecret = $customClientSecret ?? $domainCredentials['client_secret'];
        }
    }
    // Validate service is supported
    $supportedServices = ['twitch', 'discord'];
    if (!in_array($service, $supportedServices)) {
        die('Error: Unsupported service. Supported services: ' . implode(', ', $supportedServices));
    }
    // Security: Validate the domain is in our database whitelist
    if (!isAllowedDomain($originDomain)) {
        die('Error: Unauthorized domain');
    }
    // Require return_url parameter
    if (!isset($_GET['return_url']) || empty($_GET['return_url'])) {
        http_response_code(400);
        die('Error: return_url parameter is required');
    }
    $returnUrl = $_GET['return_url'];
    // Security: Ensure return URL's domain matches the login domain (exact or based on config)
    if (!is_valid_return_url_for_origin($returnUrl, $originDomain)) {
        http_response_code(403);
        die('Error: Return URL domain does not match origin domain. Security violation detected.');
    }
    // Store session data for callback
    $_SESSION['auth_service'] = $service;
    $_SESSION['origin_domain'] = $originDomain;
    $_SESSION['return_url'] = $returnUrl;
    $_SESSION['requested_scopes'] = $requestedScopes;
    // Store custom credentials if provided
    if ($customClientId && $customClientSecret) {
        $_SESSION['custom_client_id'] = $customClientId;
        $_SESSION['custom_client_secret'] = $customClientSecret;
    }
    // Route to appropriate OAuth handler
    switch ($service) {
        case 'twitch':
            $authUrl = buildTwitchAuthUrl($requestedScopes, $customClientId, $originDomain);
            break;
        case 'discord':
            $authUrl = buildDiscordAuthUrl($requestedScopes, $customClientId, $originDomain);
            break;
        default:
            die('Error: Service handler not implemented');
    }
    // Redirect to OAuth provider
    header('Location: ' . $authUrl);
    exit;
}

/**
 * Build Twitch OAuth authorization URL
 */
function buildTwitchAuthUrl($scopes, $customClientId = null, $originDomain = null) {
    // Use custom client ID if provided, otherwise try domain-specific (which includes owner's default)
    if (!$customClientId && $originDomain) {
        $domainCreds = getOAuthCredentialsForDomain('twitch', $originDomain);
        $customClientId = $domainCreds['client_id'] ?? null;
    }
    // If still no client ID, error out
    if (!$customClientId) {
        die('Error: No OAuth credentials configured for Twitch. Please contact the domain owner.');
    }
    $clientId = $customClientId;
    $params = [
        'client_id' => $clientId,
        'redirect_uri' => REDIRECT_URI,
        'response_type' => 'code',
        'scope' => $scopes,
        'state' => bin2hex(random_bytes(16)) // CSRF protection
    ];
    $_SESSION['oauth_state'] = $params['state'];
    return 'https://id.twitch.tv/oauth2/authorize?' . http_build_query($params);
}

/**
 * Build Discord OAuth authorization URL
 */
function buildDiscordAuthUrl($scopes, $customClientId = null, $originDomain = null) {
    // Use custom client ID if provided, otherwise try domain-specific (which includes owner's default)
    if (!$customClientId && $originDomain) {
        $domainCreds = getOAuthCredentialsForDomain('discord', $originDomain);
        $customClientId = $domainCreds['client_id'] ?? null;
    }
    // If still no client ID, error out
    if (!$customClientId) {
        die('Error: No OAuth credentials configured for Discord. Please contact the domain owner.');
    }
    $clientId = $customClientId;
    $params = [
        'client_id' => $clientId,
        'redirect_uri' => REDIRECT_URI,
        'response_type' => 'code',
        'scope' => $scopes,
        'state' => bin2hex(random_bytes(16)) // CSRF protection
    ];
    $_SESSION['oauth_state'] = $params['state'];
    return 'https://discord.com/api/oauth2/authorize?' . http_build_query($params);
}

// If user is logged in, check authorization and redirect or show access-denied
if (isset($_SESSION['user_id'])) {
    $loggedInTwitchId = $_SESSION['user_id'];
    $loggedInUserLogin = $_SESSION['user_login'];
    $loggedInDisplayName = $_SESSION['user_display_name'];
    $loggedInEmail = $_SESSION['user_email'] ?? '';
    $isAuthorized = isWhitelistedUser($loggedInTwitchId);
    // Fallback: check by username for users not yet migrated to ID-based lookup
    if (!$isAuthorized) {
        $conn = getStreamersConnectDB();
        if ($conn) {
            $stmt = $conn->prepare("SELECT id FROM dashboard_whitelist WHERE user_login = ? AND (twitch_id IS NULL OR twitch_id = '') AND allow = 1");
            $stmt->bind_param('s', $loggedInUserLogin);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $isAuthorized = true;
            }
            $stmt->close();
        }
    }
    // Register every logged-in user in the whitelist table with allow=0 if not already present.
    // On duplicate (twitch_id), update login/display/email/last_login but never downgrade allow.
    $conn = getStreamersConnectDB();
    if ($conn) {
        $stmt = $conn->prepare("
            INSERT INTO dashboard_whitelist (user_login, twitch_id, display_name, email, allow, added_by, notes)
            VALUES (?, ?, ?, ?, 0, 'system', 'Auto-registered on login')
            ON DUPLICATE KEY UPDATE
                user_login    = VALUES(user_login),
                display_name  = VALUES(display_name),
                email         = VALUES(email),
                last_login    = NOW(),
                updated_at    = NOW()
        ");
        $stmt->bind_param('ssss', $loggedInUserLogin, $loggedInTwitchId, $loggedInDisplayName, $loggedInEmail);
        $stmt->execute();
        $stmt->close();
    }
} else {
    $isAuthorized = false;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StreamersConnect - Authentication Service</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.0/css/all.min.css">
    <link rel="stylesheet" href="custom.css?v=<?php echo filemtime(__DIR__ . '/custom.css'); ?>">
</head>
<body>
    <?php if (isset($_SESSION['user_id']) && $isAuthorized): ?>
        <!-- Authorized user -->
        <div class="container container-dark">
            <div class="logo"><i class="fas fa-lock"></i></div>
            <h1>StreamersConnect</h1>
            <p class="subtitle">Partner Portal</p>
            <div class="center-row">
                <a href="?logout=1" class="btn btn-logout zero-margin">Logout</a>
            </div>
            <div class="info-box">
                <h3><i class="fas fa-user"></i> Welcome, <?php echo htmlspecialchars($_SESSION['user_display_name']); ?>!</h3>
            </div>
            <div class="info-box">
                <h3><i class="fas fa-gauge"></i> Dashboard</h3>
                <p>Manage your integrations, view analytics, and configure OAuth applications.</p>
                <a href="dashboard.php" class="btn btn-light mt-1rem">
                    <i class="fas fa-gauge"></i> Go to Dashboard
                </a>
            </div>
        </div>
    <?php elseif (isset($_SESSION['user_id'])): ?>
        <!-- Unauthorized logged-in user - permission required -->
        <div class="container container-dark">
            <div class="logo"><i class="fas fa-lock"></i></div>
            <h1>StreamersConnect</h1>
            <p class="subtitle">Authentication Service</p>
            <div class="center-row">
                <a href="?logout=1" class="btn btn-logout zero-margin">Logout</a>
            </div>
            <div class="info-box">
                <h3><i class="fas fa-user"></i> Welcome, <?php echo htmlspecialchars($_SESSION['user_display_name']); ?>!</h3>
            </div>
            <div class="info-box">
                <h3><i class="fas fa-circle-exclamation"></i> Access Required</h3>
                <p>Your account does not currently have permission to access the StreamersConnect dashboard or manage service settings.</p>
                <p class="mt-1rem">If you would like to use our unified login system, you may request access. Permission to use our service is granted solely at the discretion of <strong>YourStreamingTools</strong>, a subsidiary of LochStudios.</p>
                <p class="mt-1rem">To enquire, please email: <a href="mailto:partners@streamingtools.com">partners@streamingtools.com</a></p>
            </div>
        </div>
    <?php else: ?>
        <!-- Public landing page -->
        <div class="container container-dark">
            <div class="logo"><i class="fas fa-lock"></i></div>
            <h1>StreamersConnect</h1>
            <p class="subtitle">Authentication Service for StreamingTools Services</p>
            <a href="?login=streamersconnect.com&service=twitch&scopes=user:read:email&return_url=https://streamersconnect.com/" class="btn">
                <i class="fab fa-twitch"></i> Login with Twitch
            </a>
            <div class="info-box">
                <h3>How It Works</h3>
                <p>StreamersConnect provides centralized OAuth authentication for our family of streaming services and authorized partner applications.</p>
            </div>
            <div class="info-box">
                <h3>Services Enabled</h3>
                <ul class="feature-list">
                    <li><i class="fab fa-twitch"></i> Twitch</li>
                    <li><i class="fab fa-discord"></i> Discord</li>
                </ul>
            </div>
            <ul class="feature-list">
                <li>Centralized OAuth</li>
                <li>Secure token management</li>
                <li>Multi-service support</li>
                <li>Partner integration ready</li>
            </ul>
            <div class="info-box">
                <h3>For Authorized Services</h3>
                <p><strong>Integration:</strong><br>
                Contact the StreamingTools team for access credentials and integration documentation.</p>
                <p><strong>Custom OAuth Applications:</strong><br>
                Use your own OAuth credentials by including headers:<br>
                <code>X-OAuth-Client-ID</code> and <code>X-OAuth-Client-Secret</code><br>
                If not provided, defaults to StreamersConnect shared credentials.</p>
            </div>
            <div class="footer">
                <p>&copy; <?php echo date('Y'); ?> StreamersConnect - Part of the StreamingTools Ecosystem</p>
            </div>
        </div>
    <?php endif; ?>
</body>
</html>