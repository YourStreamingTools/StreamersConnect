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
- Twitch and/or Discord Developer Application (required)

## 🔧 Setup for Partners

### 1. Get Dashboard Access

Contact the StreamingTools team to have your Twitch account whitelisted for dashboard access at:
`https://streamersconnect.com/dashboard.php`

### 2. Create Your OAuth Application

You must create your own Twitch and/or Discord OAuth application:

1. Create a Twitch Developer Application at: <https://dev.twitch.tv/console/apps>
2. Create a Discord Application at: <https://discord.com/developers/applications> (if using Discord)
3. Set redirect URL to: `https://streamersconnect.com/callback.php`
4. Copy your Client ID and Client Secret
5. Add them in the StreamersConnect dashboard under "OAuth Application Management"
6. You can set one app as default for all domains, or assign specific apps to specific domains

### 3. Add Your Domains

In the dashboard:

1. Navigate to "Allowed Domains Management"
2. Click "Add New Domain"
3. Enter your domain (e.g., `yourdomain.com`)
4. Optionally assign a specific OAuth app
5. Add notes for reference

### 4. Configure OAuth Scopes

Customize which scopes your service requests:

- **Twitch Scopes**: Define required permissions (default: `user:read:email`)
- **Discord Scopes**: Define required permissions (default: `identify email guilds`)

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
    'return_url' => 'https://example.com/auth/callback.php' // Required
]);

header('Location: ' . $authUrl);
exit;
```

##### Alternative: Pass OAuth Credentials via Headers

If you prefer not to configure OAuth apps in the dashboard, you can pass your Client ID and Secret directly in the request headers:

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
    'return_url' => 'https://example.com/auth/callback.php'
]);

// Initialize cURL for header support
$ch = curl_init($authUrl);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'HTTP_X_OAUTH_CLIENT_ID: your_twitch_client_id',
    'HTTP_X_OAUTH_CLIENT_SECRET: your_twitch_client_secret'
]);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);
curl_close($ch);
```

**Note:** When using custom headers, your credentials are securely passed and used only for that specific authentication request. They are not stored.

#### Step 2: Handle the Callback

Create a callback handler at the URL you specified in `return_url`. StreamersConnect will redirect users back to this URL with authentication data.

**You must provide the `return_url` parameter** in Step 1. Implement your callback handler however you need - this is just a basic example:

```php
<?php
session_start();

// Preferred flow: verify signed payload server-side
if (isset($_GET['auth_data_sig'])) {
    $sig = $_GET['auth_data_sig'];
    $ch = curl_init('https://streamersconnect.com/verify_auth_sig.php');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['auth_data_sig' => $sig]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'X-API-Key: "<your_api_key>"']);
    $res = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($res && $http === 200) {
        $payload = json_decode($res, true);
        if (!empty($payload['success']) && !empty($payload['payload'])) {
            $authData = $payload['payload'];
            // proceed: store tokens, create session, etc.
        }
    }
} elseif (isset($_GET['server_token'])) {
    // Alternative: exchange server_token for payload
    $token = $_GET['server_token'];
    $ch = curl_init('https://streamersconnect.com/token_exchange.php');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['server_token' => $token]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'X-API-Key: "<your_api_key>"']);
    $res = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($res && $http === 200) {
        $payload = json_decode($res, true);
        if (!empty($payload['success']) && !empty($payload['payload'])) {
            $authData = $payload['payload'];
            // proceed
        }
    }
} else {
    // Legacy fallback (deprecated): decode base64 auth_data
    $authData = json_decode(base64_decode($_GET['auth_data'] ?? ''), true);
}

// Handle authData or errors as needed
if (!empty($authData) && !empty($authData['success'])) {
    $_SESSION['twitch_access_token'] = $authData['access_token'];
    $_SESSION['twitch_user'] = $authData['user'];
    header('Location: /dashboard.php');
    exit;
}

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
| `return_url` | Yes | Your callback URL to receive auth data | `https://yourdomain.com/callback` |

### Response Parameters (returned to your service)

Primary response methods are `auth_data_sig` (signed payload) or `server_token` (short-lived). When verified or exchanged server-side they return the auth payload shown below. (A legacy `auth_data` base64 JSON may still be present for compatibility but is deprecated.)

The authentication payload has the following structure:

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
├── index.php                 # Main entry point
├── dashboard.php             # Admin dashboard
├── callback.php              # OAuth callback handler
├── token_exchange.php        # Server-side token exchange endpoint
├── verify_auth_sig.php       # Signed payload verification endpoint
├── api_clients.php           # API key management endpoints (admin)
├── signing_keys.php          # Signing key management (admin)
├── scripts/
│   └── cleanup_tokens.php    # Cron job for cleaning expired tokens
├── config.example.php        # Configuration template
└── README.md                 # This file
```

Note: Admin endpoints and management pages require a whitelisted dashboard account or admin privileges.

## 📝 Architecture

StreamersConnect is a **stateless authentication proxy**. It doesn't store any tokens or user data - it simply:

1. Receives authentication requests from your services
2. Handles the Twitch OAuth flow
3. Returns the authentication data back to the requesting service

Your services are responsible for storing tokens and managing user sessions.

## 🔄 Workflow

1. **User** clicks login on `yourdomain.com`
2. **yourdomain.com** redirects to StreamersConnect with domain, scopes and `return_url`
3. **StreamersConnect** selects the OAuth app and redirects the user to Twitch/Discord for authorization
4. **User** authorizes the application
5. Twitch/Discord redirects back to StreamersConnect's callback
6. **StreamersConnect** exchanges the authorization code for an access token and fetches user data
7. **StreamersConnect** issues a response and redirects the user back to your `return_url` with one or both of:
   - `auth_data_sig` (signed payload, preferred)
   - `server_token` (short-lived single-use token)
8. Your service should verify the response server-side:
   - Call `verify_auth_sig.php` with `auth_data_sig` and your API key (preferred), or
   - Exchange `server_token` via `token_exchange.php` with your API key
9. On successful verification/exchange, **yourdomain.com** stores tokens, creates a user session, and proceeds
10. **StreamersConnect** may trigger webhooks (if configured) to notify downstream services about authentication events
11. If verification fails, treat the flow as an authentication failure and handle accordingly (log, alert, retry, or show an error).

---

### On verification failure — recommended steps

- Log the failure with request id, timestamp, origin, and HTTP status for diagnostics.
- Return an appropriate HTTP response to the user/service:
  - 401 Unauthorized — missing or invalid credentials
  - 403 Forbidden — revoked or inactive API key
  - 400 Bad Request — malformed payload
- Show a clear, user-friendly message (e.g., "Authentication failed — please sign in again") and offer a retry path.
- Emit a metric (counter) and alert if failures spike to detect systemic issues quickly.

---

### Quick flow diagram (ASCII)

```text
User -> yourdomain.com (start auth) -> StreamersConnect -> Twitch (user authorizes)
  Twitch -> StreamersConnect (code) -> StreamersConnect exchanges code and fetches user
  StreamersConnect -> yourdomain.com with auth_data_sig and/or server_token
  yourdomain.com -> (server-side) verify_auth_sig.php or token_exchange.php -> success -> create session
                                                            \-> failure -> log + show user error
```

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

Manage your OAuth applications (required):

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
- **Assign OAuth Apps**: Select which OAuth app each domain uses
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

## 📄 License

Proprietary - For use with StreamingTools ecosystem services and authorized partners only

## 👤 Author

StreamingTools Team

## 🤝 Support

For integration requests or technical support, contact the StreamingTools development team.

### Requesting Access

To integrate your service with StreamersConnect:

1. Contact the StreamingTools team
2. Provide your Twitch account username for dashboard whitelist
3. Once whitelisted, login to the dashboard at `https://streamersconnect.com/dashboard.php`
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
