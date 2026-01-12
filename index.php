<?php
session_start();

// Load configuration
require_once '/var/www/config/streamersconnect.php';

/**
 * Main handler for incoming authentication requests
 */
if (isset($_GET['service']) && isset($_GET['login']) && isset($_GET['scopes'])) {
    // Get and validate parameters
    $service = strtolower(filter_var($_GET['service'], FILTER_SANITIZE_STRING));
    $originDomain = filter_var($_GET['login'], FILTER_SANITIZE_STRING);
    $requestedScopes = filter_var($_GET['scopes'], FILTER_SANITIZE_STRING);
    // Validate service is supported
    $supportedServices = ['twitch', 'discord'];
    if (!in_array($service, $supportedServices)) {
        die('Error: Unsupported service. Supported services: ' . implode(', ', $supportedServices));
    }
    // Security: Validate the domain is in our whitelist
    if (!in_array($originDomain, $ALLOWED_DOMAINS)) {
        die('Error: Unauthorized domain');
    }
    // Store session data for callback
    $_SESSION['auth_service'] = $service;
    $_SESSION['origin_domain'] = $originDomain;
    $_SESSION['return_url'] = isset($_GET['return_url']) ? $_GET['return_url'] : "https://{$originDomain}/auth/callback";
    $_SESSION['requested_scopes'] = $requestedScopes;
    // Route to appropriate OAuth handler
    switch ($service) {
        case 'twitch':
            $authUrl = buildTwitchAuthUrl($requestedScopes);
            break;
        case 'discord':
            $authUrl = buildDiscordAuthUrl($requestedScopes);
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
function buildTwitchAuthUrl($scopes) {
    $params = [
        'client_id' => TWITCH_CLIENT_ID,
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
function buildDiscordAuthUrl($scopes) {
    $params = [
        'client_id' => DISCORD_CLIENT_ID,
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
    <link rel="stylesheet" href="custom.css">
</head>
<body>
    <div class="container">
        <div class="logo">🔐</div>
        <h1>StreamersConnect</h1>
        <p class="subtitle">Authentication Service for StreamingTools Services</p>
        <div class="info-box">
            <h3>How It Works</h3>
            <p>StreamersConnect provides centralized OAuth authentication for our family of streaming services and authorized partner applications.</p>
        </div>
        <div class="info-box">
            <h3>Services Enabled</h3>
            <ul class="feature-list">
                <li>🎮 Twitch</li>
                <li>💬 Discord</li>
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
        </div>
        <div class="footer">
            <p>&copy; <?php echo date('Y'); ?> StreamersConnect - Part of the StreamingTools Ecosystem</p>
        </div>
    </div>
</body>
</html>