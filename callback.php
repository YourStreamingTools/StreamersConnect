<?php
session_start();

// Load configuration
require_once 'config.php';

/**
 * Handle OAuth callback from Twitch
 */
if (isset($_GET['code']) && isset($_GET['state'])) {
    // Verify state to prevent CSRF attacks
    if (!isset($_SESSION['oauth_state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
        die('Error: Invalid state parameter. Possible CSRF attack.');
    }
    // Get the authorization code
    $authCode = $_GET['code'];
    // Exchange authorization code for access token
    $tokenData = exchangeCodeForToken($authCode);
    if ($tokenData === false) {
        die('Error: Failed to exchange authorization code for access token.');
    }
    // Get user information from Twitch
    $userData = getTwitchUserData($tokenData['access_token']);
    if ($userData === false) {
        die('Error: Failed to retrieve user data from Twitch.');
    }
    // Prepare data to send back to the originating service
    $returnData = [
        'success' => true,
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
    // Get the return URL from session
    $returnUrl = $_SESSION['return_url'] ?? null;
    $originDomain = $_SESSION['origin_domain'] ?? null;
    if (!$returnUrl || !$originDomain) {
        die('Error: No return URL found in session.');
    }
    // Clear session data
    unset($_SESSION['oauth_state'], $_SESSION['return_url'], $_SESSION['origin_domain'], $_SESSION['requested_scopes']);
    // Encode the data as JWT or encrypted string (for production, use proper encryption)
    $encodedData = base64_encode(json_encode($returnData));
    // Redirect back to the originating service with the auth data
    $separator = strpos($returnUrl, '?') !== false ? '&' : '?';
    header('Location: ' . $returnUrl . $separator . 'auth_data=' . urlencode($encodedData));
    exit;
}

// Handle OAuth errors
if (isset($_GET['error'])) {
    $error = $_GET['error'];
    $errorDescription = $_GET['error_description'] ?? 'Unknown error';
    $returnUrl = $_SESSION['return_url'] ?? null;
    if ($returnUrl) {
        $separator = strpos($returnUrl, '?') !== false ? '&' : '?';
        header('Location: ' . $returnUrl . $separator . 'error=' . urlencode($error) . '&error_description=' . urlencode($errorDescription));
        exit;
    } else {
        die('Authentication Error: ' . htmlspecialchars($errorDescription));
    }
}

/**
 * Exchange authorization code for access token
 */
function exchangeCodeForToken($code) {
    $tokenUrl = 'https://id.twitch.tv/oauth2/token';
    $postData = [
        'client_id' => TWITCH_CLIENT_ID,
        'client_secret' => TWITCH_CLIENT_SECRET,
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
function getTwitchUserData($accessToken) {
    $userUrl = 'https://api.twitch.tv/helix/users';
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $userUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken,
        'Client-Id: ' . TWITCH_CLIENT_ID
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Processing Authentication...</title>
    <link rel="stylesheet" href="custom.css">
</head>
<body>
    <div class="loader">
        <div class="spinner"></div>
        <h2>Processing Authentication...</h2>
        <p>Please wait while we redirect you back to your service.</p>
    </div>
</body>
</html>