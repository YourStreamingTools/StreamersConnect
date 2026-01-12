<?php
session_start();

// Handle auth callback
if (isset($_GET['auth_data'])) {
    $authData = json_decode(base64_decode($_GET['auth_data']), true);
    if (isset($authData['success']) && $authData['success'] && $authData['service'] === 'twitch') {
        // Store user session
        $_SESSION['user_id'] = $authData['user']['id'];
        $_SESSION['user_login'] = $authData['user']['login'];
        $_SESSION['user_display_name'] = $authData['user']['display_name'];
        $_SESSION['user_email'] = $authData['user']['email'];
        $_SESSION['access_token'] = $authData['access_token'];
    }
    // Redirect to clean URL
    header('Location: https://streamersconnect.com/');
    exit;
}

// Handle error
if (isset($_GET['error'])) {
    header('Location: https://streamersconnect.com/?error=' . urlencode($_GET['error']));
    exit;
}

// If accessed directly without auth data, redirect to home
header('Location: https://streamersconnect.com/');
exit;
