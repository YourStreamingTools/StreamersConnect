<?php
/**
 * StreamersConnect Configuration Example
 * 
 * Copy this structure to your server's config directory and fill in your credentials.
 */

// Twitch Application Credentials
// Get these from https://dev.twitch.tv/console/apps
// Create a new application and set the OAuth Redirect URL to: https://yourdomain.com/callback.php
define('TWITCH_CLIENT_ID', 'your_twitch_client_id_here');
define('TWITCH_CLIENT_SECRET', 'your_twitch_client_secret_here');

// Discord Application Credentials
// Get these from https://discord.com/developers/applications
// Create a new application, go to OAuth2 settings, and add redirect URL: https://yourdomain.com/callback.php
define('DISCORD_CLIENT_ID', 'your_discord_client_id_here');
define('DISCORD_CLIENT_SECRET', 'your_discord_client_secret_here');

// Your StreamersConnect domain
define('STREAMERS_CONNECT_DOMAIN', 'streamersconnect.com');
define('REDIRECT_URI', 'https://' . STREAMERS_CONNECT_DOMAIN . '/callback.php');
define('INTERNAL_DASHBOARD_URL', 'https://' . STREAMERS_CONNECT_DOMAIN . '/dashboard.php');

// Whitelist of allowed domains that can use this auth service
// Add all your domains here for security
$ALLOWED_DOMAINS = [
    'streamersconnect.com',
    'www.streamersconnect.com',
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