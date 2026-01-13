# StreamersConnect - Authentication Service

A centralized OAuth authentication service for the StreamingTools ecosystem and authorized partner applications.

## 🎯 Purpose

StreamersConnect acts as a central authentication hub that handles Twitch OAuth connections for our family of streaming services and authorized partner applications. Instead of managing OAuth credentials and flows in each service, authentication requests are forwarded to StreamersConnect, which handles the OAuth flow and returns the authentication data to the requesting service.

## 🚀 Features

- **Centralized OAuth Management**: Handle Twitch authentication in one place
- **Multi-Service Support**: Support multiple authorized domains/services with one auth system
- **Secure Token Exchange**: Safely exchange authorization codes for access tokens
- **Flexible Scopes**: Each service can request different OAuth scopes
- **Partner Integration**: Simple URL-based API for authorized services

## 📋 Prerequisites

- PHP 7.4 or higher
- cURL extension enabled
- HTTPS enabled (required for OAuth)
- Twitch Developer Application (managed by StreamingTools team)
- Domain whitelist approval for integration

## 🔧 Setup

### 1. Configure Twitch Application

The Twitch application is managed by the StreamingTools team.
The OAuth Redirect URL is configured as: `https://streamersconnect.com/callback.php`

### 2. Configure StreamersConnect

**For StreamingTools Team:**

1. Copy `config.example.php` to `config.php`
2. Fill in your Twitch Client ID and Client Secret
3. Add all allowed domains to the whitelist
4. Update the domain name if not using `streamersconnect.com`

### 3. Update index.php and callback.php

Replace the configuration constants in both files with your actual credentials, or better yet, include the config file:

```php
require_once 'config.php';
```

## 💻 Integration Guide

### For Authorized Services

**Note:** Your domain must be added to the whitelist by the StreamingTools team before integration.

### From Your Service (e.g., botofthespecter.com)

#### Step 1: Redirect to StreamersConnect

In your login.php or wherever you initiate authentication:

```php
$scopes = [
    'user:read:email',
    'channel:read:subscriptions',
    'chat:read',
    'chat:edit'
];

$authUrl = 'https://streamersconnect.com?' . http_build_query([
    'login' => 'botofthespecter.com',
    'scopes' => implode(' ', $scopes),
    'return_url' => 'https://botofthespecter.com/auth/callback.php' // Optional
]);

header('Location: ' . $authUrl);
exit;
```

#### Step 2: Handle the Callback

Create `/auth/callback.php` on your service to receive the authentication data:

```php
<?php
session_start();

if (isset($_GET['auth_data'])) {
    $encodedData = $_GET['auth_data'];
    $authData = json_decode(base64_decode($encodedData), true);
    
    if ($authData && $authData['success']) {
        // Store the authentication data
        $_SESSION['twitch_access_token'] = $authData['access_token'];
        $_SESSION['twitch_refresh_token'] = $authData['refresh_token'];
        $_SESSION['twitch_user'] = $authData['user'];
        
        // Redirect to your dashboard
        header('Location: /dashboard.php');
        exit;
    }
}

// Handle error
if (isset($_GET['error'])) {
    die('Authentication failed: ' . htmlspecialchars($_GET['error_description']));
}
?>
```

## 📊 URL Parameters

### Request Parameters (sent to StreamersConnect)

| Parameter | Required | Description | Example |
| --------- | -------- | ----------- | ------- |
| `login` | Yes | The domain of your service | `botofthespecter.com` |
| `scopes` | Yes | Space-separated OAuth scopes | `user:read:email chat:read` |
| `return_url` | No | Custom callback URL | `https://yourdomain.com/callback` |

### Response Parameters (returned to your service)

The authentication data is returned as a base64-encoded JSON object in the `auth_data` parameter:

```json
{
    "success": true,
    "access_token": "...",
    "refresh_token": "...",
    "expires_in": 3600,
    "scope": ["user:read:email", "chat:read"],
    "token_type": "bearer",
    "user": {
        "id": "12345678",
        "login": "username",
        "display_name": "Username",
        "email": "user@example.com",
        "profile_image_url": "https://...",
        "broadcaster_type": "partner"
    }
}
```

## 🔒 Security Features

- **Domain Whitelist**: Only pre-approved domains can use the service
- **CSRF Protection**: State parameter validation prevents CSRF attacks
- **Secure Token Exchange**: Server-to-server communication for token exchange
- **HTTPS Required**: OAuth requires secure connections

## 🗂️ File Structure

```text
StreamersConnect/
├── index.php                                 # Main entry point
├── callback.php                              # OAuth callback handler
├── config.php                                # Configuration (create from config.example.php)
├── config.example.php                        # Configuration template
├── example-integration-botofthespecter.php   # Integration example
└── README.md                                 # This file
```

## 📝 Architecture

StreamersConnect is a **stateless authentication proxy**. It doesn't store any tokens or user data - it simply:

1. Receives authentication requests from your services
2. Handles the Twitch OAuth flow
3. Returns the authentication data back to the requesting service

Your services are responsible for storing tokens and managing user sessions.

## 🔄 Workflow

1. **User** clicks login on `botofthespecter.com`
2. **botofthespecter.com** redirects to StreamersConnect with domain and scopes
3. **StreamersConnect** redirects user to Twitch OAuth
4. **User** authorizes the application on Twitch
5. **Twitch** redirects back to StreamersConnect callback
6. **StreamersConnect** exchanges code for access token
7. **StreamersConnect** fetches user data from Twitch
8. **StreamersConnect** redirects back to botofthespecter.com with auth data
9. **botofthespecter.com** stores the tokens and user data

## 📝 Available Twitch Scopes

Common scopes you might need:

- `user:read:email` - Read user email
- `channel:read:subscriptions` - Read channel subscriptions
- `channel:manage:redemptions` - Manage channel point redemptions
- `chat:read` - Read chat messages
- `chat:edit` - Send chat messages
- `moderator:read:followers` - Read follower list
- `bits:read` - View bits information
- `channel:read:redemptions` - Read channel point redemptions

[Full list of Twitch scopes](https://dev.twitch.tv/docs/authentication/scopes)

## 🐛 Troubleshooting

### "Unauthorized domain" error

- Make sure your domain is added to the `$ALLOWED_DOMAINS` array in index.php

### "Invalid state parameter" error

- This indicates a potential CSRF attack or session issues
- Make sure sessions are working properly
- Check that cookies are enabled

### "Failed to exchange authorization code"

- Verify your Client ID and Client Secret are correct
- Make sure the redirect URI in Twitch console matches exactly
- Check that cURL is enabled in PHP

## 📈 Dashboard & Monitoring

StreamersConnect includes a powerful dashboard for monitoring authentication activity across all connected domains.

### Dashboard Access

The dashboard is available at `https://streamersconnect.com/dashboard.php` after logging in with your Twitch account.

**Access Levels:**

- **Whitelisted Users**: Full access to real authentication data and analytics
- **Regular Users**: Preview mode with placeholder data

### Features for Whitelisted Users

#### Real-time Analytics

- **Total Authentications**: Overall count of all authentication attempts
- **Monthly Stats**: Number of authentications in the current month
- **Success Rate**: Percentage of successful authentications

#### Domain-Specific Statistics

View authentication breakdown by domain

For each domain see:

- Total authentication count
- Success rate
- Last authentication timestamp

#### Recent Activity Log

Monitor the last 20 authentication attempts with:

- Timestamp (relative time: "5m ago", "2h ago")
- Service (Twitch/Discord)
- Origin domain
- Username
- Success/failure status with error details

### Database Structure

StreamersConnect uses a MySQL database to track all authentication activity.

**Tables:**

- `auth_logs` - Every authentication attempt (success/failure)
- `dashboard_whitelist` - Users with full dashboard access
- `oauth_applications` - (Future) Partner OAuth applications

### Accessing Statistics

Whitelisted users can view detailed statistics at:

- **Dashboard**: `https://streamersconnect.com/dashboard.php` - Overview with recent activity
- **Detailed Stats**: `https://streamersconnect.com/stats.php` - Comprehensive analytics

The stats page shows:

- Overall authentication statistics
- Stats broken down by domain
- Stats broken down by service (Twitch/Discord)
- Recent failed authentications with error details
- Unique user counts

### Managing Whitelist

To add users to the whitelist, insert directly into the database:

```sql
INSERT INTO streamersconnect.dashboard_whitelist (user_login, notes, added_by) 
VALUES ('username', 'Reason for access', 'admin_name');
```

Check current whitelist:

```sql
SELECT user_login, notes, created_at FROM streamersconnect.dashboard_whitelist;
```

Remove from whitelist:

```sql
DELETE FROM streamersconnect.dashboard_whitelist WHERE user_login = 'username';
```

## 📄 License

Proprietary - For use with StreamingTools ecosystem services and authorized partners only

## 👤 Author

StreamingTools Team

## 🤝 Support

For integration requests or technical support, contact the StreamingTools development team.

### Requesting Access

To integrate your service with StreamersConnect:

1. Contact the StreamingTools team
2. Provide your domain(s) for whitelist approval
3. Review integration documentation and best practices
4. Receive access credentials and support for implementation

---

**Note**: Never commit your `config.php` file with real credentials to version control. Always use `config.example.php` as a template.
