<?php
session_start();

// Load configuration
require_once '/var/www/config/streamersconnect.php';

/**
 * Main handler for incoming authentication requests
 */
if (isset($_GET['login']) && isset($_GET['scopes'])) {
    // Get and validate the originating domain
    $originDomain = filter_var($_GET['login'], FILTER_SANITIZE_STRING);
    $requestedScopes = filter_var($_GET['scopes'], FILTER_SANITIZE_STRING);
    // Security: Validate the domain is in our whitelist
    if (!in_array($originDomain, $ALLOWED_DOMAINS)) {
        die('Error: Unauthorized domain');
    }
    // Store the origin domain and return URL in session for callback
    $_SESSION['origin_domain'] = $originDomain;
    $_SESSION['return_url'] = isset($_GET['return_url']) ? $_GET['return_url'] : "https://{$originDomain}/auth/callback";
    $_SESSION['requested_scopes'] = $requestedScopes;
    // Build Twitch OAuth URL
    $twitchAuthUrl = buildTwitchAuthUrl($requestedScopes);
    // Redirect to Twitch for authentication
    header('Location: ' . $twitchAuthUrl);
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
        <ul class="feature-list">
            <li>Centralized Twitch OAuth</li>
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