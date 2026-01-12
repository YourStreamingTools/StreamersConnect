<?php
/**
 * StreamersConnect Configuration
 * 
 * Copy this file to config.php and fill in your actual values
 */

// Twitch Application Credentials
// Get these from https://dev.twitch.tv/console/apps
define('TWITCH_CLIENT_ID', 'your_client_id_here');
define('TWITCH_CLIENT_SECRET', 'your_client_secret_here');

// Your StreamersConnect domain
define('STREAMERS_CONNECT_DOMAIN', 'streamersconnect.com');
define('REDIRECT_URI', 'https://' . STREAMERS_CONNECT_DOMAIN . '/callback.php');

// Whitelist of allowed domains that can use this auth service
// Add all your domains here for security
$ALLOWED_DOMAINS = [
    'botofthespecter.com',
    'www.botofthespecter.com',
    // Add more domains as needed
];

// Security settings
define('SESSION_LIFETIME', 3600); // 1 hour
define('USE_SECURE_COOKIES', true); // Set to true in production (requires HTTPS)

// Logging (optional)
define('ENABLE_ERROR_LOGGING', true);
define('LOG_FILE', __DIR__ . '/logs/auth.log');

// Optional: Rate limiting
define('ENABLE_RATE_LIMITING', false);
define('MAX_REQUESTS_PER_IP', 10); // per minute
?>