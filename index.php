<?php
session_start();

// Load configuration
require_once '/var/www/config/streamersconnect.php';

// Handle auth callback for internal login
if (isset($_GET['auth_data'])) {
    $authData = json_decode(base64_decode($_GET['auth_data']), true);
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
    $service = strtolower(filter_var($_GET['service'], FILTER_SANITIZE_STRING));
    $originDomain = filter_var($_GET['login'], FILTER_SANITIZE_STRING);
    // Set default Twitch scope if none provided
    $requestedScopes = isset($_GET['scopes']) && trim($_GET['scopes']) !== '' ? filter_var($_GET['scopes'], FILTER_SANITIZE_STRING) : null;
    if ($service === 'twitch' && (!$requestedScopes || $requestedScopes === '')) {
        $requestedScopes = 'user:read:email';
    }
    // Check for custom OAuth credentials in headers
    $customClientId = $_SERVER['HTTP_X_OAUTH_CLIENT_ID'] ?? null;
    $customClientSecret = $_SERVER['HTTP_X_OAUTH_CLIENT_SECRET'] ?? null;
    // Validate service is supported
    $supportedServices = ['twitch', 'discord'];
    if (!in_array($service, $supportedServices)) {
        die('Error: Unsupported service. Supported services: ' . implode(', ', $supportedServices));
    }
    // Security: Validate the domain is in our whitelist
    if (!in_array($originDomain, $ALLOWED_DOMAINS)) {
        die('Error: Unauthorized domain');
    }
    // Require return_url parameter
    if (!isset($_GET['return_url']) || empty($_GET['return_url'])) {
        http_response_code(400);
        die('Error: return_url parameter is required');
    }
    $returnUrl = $_GET['return_url'];
    $returnUrlHost = parse_url($returnUrl, PHP_URL_HOST);
    // Security: Ensure return URL's domain matches the login domain
    if ($returnUrlHost !== $originDomain) {
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
            $authUrl = buildTwitchAuthUrl($requestedScopes, $customClientId);
            break;
        case 'discord':
            $authUrl = buildDiscordAuthUrl($requestedScopes, $customClientId);
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
function buildTwitchAuthUrl($scopes, $customClientId = null) {
    $clientId = $customClientId ?? TWITCH_CLIENT_ID;
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
function buildDiscordAuthUrl($scopes, $customClientId = null) {
    $clientId = $customClientId ?? DISCORD_CLIENT_ID;
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StreamersConnect - Authentication Service</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.css">
    <link rel="stylesheet" href="custom.css?v=<?php echo filemtime(__DIR__ . '/custom.css'); ?>">
</head>
<body>
    <?php if (isset($_SESSION['user_id'])): ?>
        <!-- Partner Dashboard - Coming Soon -->
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
            <div class="info-box dashboard-highlight">
                <h3><i class="fas fa-rocket"></i> Partner Dashboard - Coming Soon</h3>
                <p>We're building an exclusive dashboard for authorized partners to manage their integrations, view analytics, and configure OAuth applications.</p>
                <p class="mt-1rem"><strong>Upcoming Features:</strong></p>
                <ul class="feature-list">
                    <li><i class="fas fa-key"></i> OAuth Application Management</li>
                    <li><i class="fas fa-chart-bar"></i> Authentication Analytics</li>
                    <li><i class="fas fa-cog"></i> Service Configuration</li>
                    <li><i class="fas fa-bell"></i> Webhook Management</li>
                    <li><i class="fas fa-shield-alt"></i> Security & Compliance Tools</li>
                </ul>
                <a href="dashboard.php" class="btn btn-light">
                    <i class="fas fa-eye"></i> Preview Dashboard (Non-Functional)
                </a>
            </div>
            <div class="info-box">
                <h3><i class="fas fa-handshake"></i> Become a Partner</h3>
                <p>Interested in integrating StreamersConnect into your application? Contact our team to discuss partnership opportunities and get early access to the dashboard.</p>
                <p class="mt-1rem"><strong>Email:</strong> partners@streamingtools.com</p>
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