# StreamersConnect - Authentication Service

A centralized OAuth authentication service for the StreamingTools ecosystem and authorized partner applications.

## 🎯 Purpose

StreamersConnect acts as a central authentication hub that handles Twitch OAuth connections for our family of streaming services and authorized partner applications. Instead of managing OAuth credentials and flows in each service, authentication requests are forwarded to StreamersConnect, which handles the OAuth flow and returns the authentication data to the requesting service.

## 🚀 Features

- **Centralized OAuth Management**: Handle Twitch & Discord authentication in one place
- **Multi-Service Support**: Support multiple authorized domains/services with one auth system
- **Secure Token Exchange**: Safely exchange authorization codes for access tokens
- **Flexible Scopes**: Each service can request different OAuth scopes
- **Partner Dashboard**: Self-service portal for managing OAuth apps, domains, and webhooks
- **Custom OAuth Applications**: Partners can use their own Twitch/Discord OAuth apps
- **Domain Whitelist Management**: Add and manage authorized domains through the dashboard
- **Webhook Notifications**: Real-time notifications for authentication events
- **Analytics & Monitoring**: Track authentication activity across all your domains

## 📋 Prerequisites

- PHP 7.4 or higher
- cURL extension enabled
- HTTPS enabled (required for OAuth)
- Partner dashboard access (whitelisted Twitch account)
- Twitch/Discord Developer Application (can use your own or default shared app)

## 🔧 Setup for Partners

### 1. Get Dashboard Access

Contact the StreamingTools team to have your Twitch account whitelisted for dashboard access at:
`https://streamersconnect.com/dashboard.php`

### 2. Configure Your OAuth Application (Optional)

You have two options:

#### Option A: Use Default Shared OAuth App

- No configuration needed
- Shared across all partners
- Fastest to get started

#### Option B: Use Your Own OAuth App

1. Create a Twitch/Discord Developer Application
2. Set redirect URL to: `https://streamersconnect.com/callback.php`
3. Add your Client ID and Secret in the dashboard
4. Assign it to specific domains or set as default

### 3. Add Your Domains

In the dashboard:

1. Navigate to "Allowed Domains Management"
2. Click "Add New Domain"
3. Enter your domain (e.g., `yourdomain.com`)
4. Optionally assign a specific OAuth app
5. Add notes for reference

### 4. Configure OAuth Scopes

Customize which scopes your service requests:

- **Twitch Scopes**: Default or custom scope list
- **Discord Scopes**: Default or custom scope list

### 5. Set Up Webhooks (Optional)

Receive real-time notifications for authentication events:

1. Navigate to "Webhook Management"
2. Click "Add Webhook"
3. Enter webhook URL and name
4. Generate or provide a secret for verification
5. Select events to receive (success/failure)

## 💻 Integration Guide

### For Authorized Services

**Note:** Add your domain through the partner dashboard before integration.

### Authentication Flow

#### From Your Service (e.g., yourdomain.com)

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
    'login' => 'example.com',
    'scopes' => implode(' ', $scopes),
    'return_url' => 'https://example.com/auth/callback.php' // Optional
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
| `login` | Yes | The domain of your service | `example.com` |
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

1. **User** clicks login on `yourdomain.com`
2. **yourdomain.com** redirects to StreamersConnect with domain and scopes
3. **StreamersConnect** selects appropriate OAuth app (default or domain-specific)
4. **StreamersConnect** redirects user to Twitch/Discord OAuth
5. **User** authorizes the application
6. **Twitch/Discord** redirects back to StreamersConnect callback
7. **StreamersConnect** exchanges code for access token
8. **StreamersConnect** fetches user data
9. **StreamersConnect** triggers webhooks (if configured)
10. **StreamersConnect** redirects back to yourdomain.com with auth data
11. **yourdomain.com** stores the tokens and user data

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

- Make sure your domain is added through the Partner Dashboard
- Check that the domain matches exactly (no www prefix unless specified)

### "Invalid state parameter" error

- This indicates a potential CSRF attack or session issues
- Make sure sessions are working properly
- Check that cookies are enabled

### "Failed to exchange authorization code"

- Verify your Client ID and Client Secret are correct
- Make sure the redirect URI in Twitch console matches exactly
- Check that cURL is enabled in PHP

## 📈 Partner Dashboard

StreamersConnect includes a powerful self-service dashboard for partners to manage their integrations.

### Accessing the Dashboard

Login at `https://streamersconnect.com/dashboard.php` with your whitelisted Twitch account.

### Dashboard Features

#### 1. OAuth Application Management

Manage your own OAuth applications or use the default shared one:

- **Create Applications**: Add Twitch or Discord OAuth apps with your Client ID/Secret
- **Set Default**: Choose which app to use across all domains
- **Domain-Specific Apps**: Assign different OAuth apps to different domains
- **Security**: Client secrets are stored securely and never exposed

##### Benefits of Custom OAuth Apps

- Your own branding in OAuth prompts
- Independent rate limits
- Better control and isolation
- Custom analytics in Twitch/Discord developer dashboards

#### 2. Domain Management

Self-service domain whitelist management:

- **Add Domains**: Whitelist domains that can use your OAuth apps
- **Assign OAuth Apps**: Use default or specific apps per domain
- **Notes**: Document why each domain is whitelisted
- **View Statistics**: See authentication activity per domain

#### 3. Webhook Management

Receive real-time notifications for authentication events:

- **Custom Endpoints**: Set up webhook URLs for your backend
- **Secure Secrets**: Generate or provide 32-character secrets for verification
- **Event Selection**: Choose to receive success, failure, or both events
- **Multiple Webhooks**: Configure different webhooks for different purposes

##### Webhook Payload Example

```json
{
  "event": "authentication_success",
  "timestamp": "2026-01-14T12:34:56Z",
  "service": "twitch",
  "domain": "yourdomain.com",
  "user": {
    "id": "12345678",
    "login": "username",
    "display_name": "Username"
  }
}
```

##### Webhook Verification

Each webhook request includes a `X-StreamersConnect-Signature` header with HMAC-SHA256 signature.

```php
$signature = hash_hmac('sha256', $requestBody, $webhookSecret);
if ($signature === $_SERVER['HTTP_X_STREAMERSCONNECT_SIGNATURE']) {
    // Webhook is authentic
}
```

#### 4. Service Configuration

Customize OAuth scopes for your integrations:

- **Twitch Scopes**: Define which permissions to request from Twitch users
- **Discord Scopes**: Define which permissions to request from Discord users
- **Easy Updates**: Change scopes without code deployments

#### 5. Analytics & Monitoring

Real-time analytics to track authentication activity:

- **Total Authentications**: Overall count of all authentication attempts
- **Monthly Stats**: Number of authentications in the current month
- **Success Rate**: Percentage of successful authentications
- **Domain Breakdown**: Authentication count and success rate per domain
- **Recent Activity**: Last 5 authentication attempts with full details

### Database Structure

StreamersConnect uses a MySQL database to manage partners and track activity.

**Tables:**

- `auth_logs` - Every authentication attempt (success/failure)
- `dashboard_whitelist` - Users with full dashboard access
- `oauth_applications` - Partner OAuth applications (Twitch/Discord)
- `allowed_domains` - Whitelisted domains with OAuth app assignments
- `webhooks` - Webhook endpoints for event notifications
- `user_service_config` - Custom OAuth scopes per partner

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

**For StreamingTools Team:**

To add users to the whitelist, insert directly into the database:

```sql
INSERT INTO streamersconnect.dashboard_whitelist (twitch_id, user_login, display_name, email, notes) 
VALUES ('123456789', 'username', 'DisplayName', 'email@example.com', 'Partner - YourCompany');
```

Check current whitelist:

```sql
SELECT user_login, display_name, notes, created_at FROM streamersconnect.dashboard_whitelist;
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
2. Provide your Twitch account for dashboard whitelist
3. Receive dashboard access credentials
4. Configure your OAuth apps and domains through the dashboard
5. Implement the integration following this documentation
6. Test in development environment
7. Launch to production

### Support Resources

- **Dashboard**: Self-service management at `https://streamersconnect.com/dashboard.php`
- **Documentation**: This README and inline help in the dashboard
- **Contact**: StreamingTools development team for technical issues

---

**Security Notes:**

- Client secrets are stored securely in the database and never exposed in logs or frontend
- Webhook secrets should be at least 32 characters with mixed case letters and numbers
- All OAuth flows use HTTPS and CSRF protection
- Never commit sensitive credentials to version control
