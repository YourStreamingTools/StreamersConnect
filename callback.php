<?php
session_start();

// Load configuration
require_once '/var/www/config/streamersconnect.php';

/**
 * Handle OAuth callback from service provider
 */
if (isset($_GET['code']) && isset($_GET['state'])) {
    // Verify state to prevent CSRF attacks
    if (!isset($_SESSION['oauth_state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
        die('Error: Invalid state parameter. Possible CSRF attack.');
    }
    // Get the authorization code and service
    $authCode = $_GET['code'];
    $service = $_SESSION['auth_service'] ?? null;
    // Validate service parameter exists
    if (!$service) {
        http_response_code(400);
        die('Error: Missing service information. Authentication request was not properly initiated.');
    }
    // Get custom credentials from session if they were provided
    $customClientId = $_SESSION['custom_client_id'] ?? null;
    $customClientSecret = $_SESSION['custom_client_secret'] ?? null;
    // Route to appropriate service handler
    $originDomain = $_SESSION['origin_domain'] ?? 'unknown';
    $requestedScopes = $_SESSION['requested_scopes'] ?? '';
    
    switch ($service) {
        case 'twitch':
            $tokenData = exchangeTwitchCodeForToken($authCode, $customClientId, $customClientSecret);
            if ($tokenData === false) {
                logAuthAttempt($service, $originDomain, [], $requestedScopes, false, 'Failed to exchange authorization code for access token');
                die('Error: Failed to exchange authorization code for access token.');
            }
            $userData = getTwitchUserData($tokenData['access_token'], $customClientId);
            if ($userData === false) {
                logAuthAttempt($service, $originDomain, [], $requestedScopes, false, 'Failed to retrieve user data from Twitch API');
                die('Error: Failed to retrieve user data from Twitch.');
            }
            break;
        case 'discord':
            $tokenData = exchangeDiscordCodeForToken($authCode, $customClientId, $customClientSecret);
            if ($tokenData === false) {
                logAuthAttempt($service, $originDomain, [], $requestedScopes, false, 'Failed to exchange authorization code for access token');
                die('Error: Failed to exchange authorization code for access token.');
            }
            $userData = getDiscordUserData($tokenData['access_token']);
            if ($userData === false) {
                logAuthAttempt($service, $originDomain, [], $requestedScopes, false, 'Failed to retrieve user data from Discord API');
                die('Error: Failed to retrieve user data from Discord.');
            }
            break;
        default:
            logAuthAttempt('unknown', $originDomain, [], $requestedScopes, false, 'Unknown service in session');
            die('Error: Unknown service in session');
    }
    // Prepare data to send back to the originating service
    $returnData = [
        'success' => true,
        'service' => $service,
        'access_token' => $tokenData['access_token'],
        'refresh_token' => $tokenData['refresh_token'],
        'expires_in' => $tokenData['expires_in'],
        'scope' => $tokenData['scope'],
        'token_type' => $tokenData['token_type'],
        'user' => [
            'id' => $userData['id'],
            'login' => $userData['login'],
            'display_name' => $userData['display_name'],
            'email' => $userData['email'] ?? null,
            'profile_image_url' => $userData['profile_image_url'],
            'broadcaster_type' => $userData['broadcaster_type']
        ]
    ];
    // Get the return URL from session (originDomain and requestedScopes already loaded above)
    $returnUrl = $_SESSION['return_url'] ?? null;
    if (!$returnUrl || !$originDomain) {
        logAuthAttempt($service ?? 'unknown', $originDomain ?? 'unknown', [], $requestedScopes, false, 'Missing return URL or origin domain in session');
        die('Error: No return URL found in session.');
    }
    // Log successful authentication
    logAuthAttempt($service, $originDomain, $returnData['user'], $requestedScopes, true);
    // Store origin domain for display (before clearing session)
    $displayOrigin = $originDomain;
    // Check if this is StreamersConnect's own authentication (dashboard or base URL)
    $internalUrls = [
        INTERNAL_DASHBOARD_URL,
        'https://' . STREAMERS_CONNECT_DOMAIN . '/',
        'https://' . STREAMERS_CONNECT_DOMAIN
    ];
    if (in_array($returnUrl, $internalUrls)) {
        // Handle internal auth directly - store session and redirect to home
        $_SESSION['user_id'] = $returnData['user']['id'];
        $_SESSION['user_login'] = $returnData['user']['login'];
        $_SESSION['user_display_name'] = $returnData['user']['display_name'];
        $_SESSION['user_email'] = $returnData['user']['email'];
        $_SESSION['access_token'] = $returnData['access_token'];
        $_SESSION['refresh_token'] = $returnData['refresh_token'];
        $_SESSION['auth_service'] = $service;
        // Clear OAuth state data
        unset($_SESSION['oauth_state'], $_SESSION['return_url'], $_SESSION['origin_domain'], $_SESSION['requested_scopes'], $_SESSION['custom_client_id'], $_SESSION['custom_client_secret']);
        // Redirect to home page
        $redirectUrl = 'https://' . STREAMERS_CONNECT_DOMAIN . '/';
    } else {
        // External service authentication - send auth_data back
        // Clear session data
        unset($_SESSION['oauth_state'], $_SESSION['return_url'], $_SESSION['origin_domain'], $_SESSION['requested_scopes'], $_SESSION['auth_service'], $_SESSION['custom_client_id'], $_SESSION['custom_client_secret']);
        // Encode the data as JWT or encrypted string (for production, use proper encryption)
        $encodedData = base64_encode(json_encode($returnData));
        // Build redirect URL
        $separator = strpos($returnUrl, '?') !== false ? '&' : '?';
        $redirectUrl = $returnUrl . $separator . 'auth_data=' . urlencode($encodedData);
    }
}

// Handle OAuth errors
if (isset($_GET['error'])) {
    $error = $_GET['error'];
    $errorDescription = $_GET['error_description'] ?? 'Unknown error';
    $returnUrl = $_SESSION['return_url'] ?? null;
    $displayOrigin = $_SESSION['origin_domain'] ?? null;
    $service = $_SESSION['auth_service'] ?? 'unknown';
    $requestedScopes = $_SESSION['requested_scopes'] ?? '';
    // Log failed authentication
    if ($displayOrigin) {
        logAuthAttempt($service, $displayOrigin, [], $requestedScopes, false, $errorDescription);
    }
    // Set error state for display
    $authError = true;
    $errorMessage = match($error) {
        'access_denied' => 'Authentication was canceled or denied.',
        'invalid_request' => 'Invalid authentication request.',
        'unauthorized_client' => 'Unauthorized client application.',
        'server_error' => 'Server error occurred during authentication.',
        default => htmlspecialchars($errorDescription)
    };
    // If we have a return URL, we'll redirect after showing error for a moment
    if ($returnUrl) {
        $separator = strpos($returnUrl, '?') !== false ? '&' : '?';
        $redirectUrl = $returnUrl . $separator . 'error=' . urlencode($error) . '&error_description=' . urlencode($errorDescription);
    }
}

/**
 * Exchange Twitch authorization code for access token
 */
function exchangeTwitchCodeForToken($code, $customClientId = null, $customClientSecret = null) {
    $tokenUrl = 'https://id.twitch.tv/oauth2/token';
    $postData = [
        'client_id' => $customClientId ?? TWITCH_CLIENT_ID,
        'client_secret' => $customClientSecret ?? TWITCH_CLIENT_SECRET,
        'code' => $code,
        'grant_type' => 'authorization_code',
        'redirect_uri' => REDIRECT_URI
    ];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $tokenUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode !== 200) {
        error_log('Twitch token exchange failed: ' . $response);
        return false;
    }
    return json_decode($response, true);
}

/**
 * Get user data from Twitch API
 */
function getTwitchUserData($accessToken, $customClientId = null) {
    $userUrl = 'https://api.twitch.tv/helix/users';
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $userUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken,
        'Client-Id: ' . ($customClientId ?? TWITCH_CLIENT_ID)
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode !== 200) {
        error_log('Twitch user data fetch failed: ' . $response);
        return false;
    }
    $data = json_decode($response, true);
    return $data['data'][0] ?? false;
}

/**
 * Exchange Discord authorization code for access token
 */
function exchangeDiscordCodeForToken($code, $customClientId = null, $customClientSecret = null) {
    $tokenUrl = 'https://discord.com/api/oauth2/token';
    $postData = [
        'client_id' => $customClientId ?? DISCORD_CLIENT_ID,
        'client_secret' => $customClientSecret ?? DISCORD_CLIENT_SECRET,
        'code' => $code,
        'grant_type' => 'authorization_code',
        'redirect_uri' => REDIRECT_URI
    ];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $tokenUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode !== 200) {
        error_log('Discord token exchange failed: ' . $response);
        return false;
    }
    return json_decode($response, true);
}

/**
 * Get user data from Discord API
 */
function getDiscordUserData($accessToken) {
    $userUrl = 'https://discord.com/api/users/@me';
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $userUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode !== 200) {
        error_log('Discord user data fetch failed: ' . $response);
        return false;
    }
    $userData = json_decode($response, true);
    // Normalize Discord user data to match expected format
    return [
        'id' => $userData['id'],
        'login' => $userData['username'],
        'display_name' => $userData['global_name'] ?? $userData['username'],
        'email' => $userData['email'] ?? null,
        'profile_image_url' => $userData['avatar'] ? "https://cdn.discordapp.com/avatars/{$userData['id']}/{$userData['avatar']}.png" : null,
        'broadcaster_type' => '' // Discord doesn't have this concept
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Processing Authentication...</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="custom.css">
</head>
<body>
    <div class="loader">
        <?php if (isset($authError) && $authError): ?>
            <div class="error-icon">✖</div>
            <h2>Authentication Failed</h2>
            <p><?php echo $errorMessage; ?></p>
                <?php if (isset($redirectUrl) && isset($displayOrigin)): ?>
                <p class="redirect-note">Redirecting back to <strong><?php echo htmlspecialchars($displayOrigin); ?></strong> in <span id="countdown">5</span> seconds...</p>
            <?php else: ?>
                <p class="mt-2rem">Please close this window and try again.</p>
            <?php endif; ?>
        <?php elseif (isset($redirectUrl)): ?>
            <div class="spinner"></div>
            <h2>Authentication Successful!</h2>
            <?php if (isset($displayOrigin)): ?>
                <p>Redirecting you back to <strong><?php echo htmlspecialchars($displayOrigin); ?></strong>...</p>
            <?php else: ?>
                <p>Redirecting you back to your service...</p>
            <?php endif; ?>
        <?php else: ?>
            <div class="spinner"></div>
            <h2>Processing Authentication...</h2>
            <p>Please wait while we redirect you back to your service.</p>
        <?php endif; ?>
    </div>
    <?php if (isset($redirectUrl)): ?>
    <script>
        <?php if (isset($authError) && $authError): ?>
        // Error redirect with countdown
        let countdown = 5;
        const countdownEl = document.getElementById('countdown');
        const timer = setInterval(function() {
            countdown--;
            if (countdownEl) countdownEl.textContent = countdown;
            if (countdown <= 0) {
                clearInterval(timer);
                window.location.href = <?php echo json_encode($redirectUrl); ?>;
            }
        }, 1000);
        <?php else: ?>
        // Success redirect
        setTimeout(function() {
            window.location.href = <?php echo json_encode($redirectUrl); ?>;
        }, 2000);
        <?php endif; ?>
    </script>
    <?php endif; ?>
</body>
</html>