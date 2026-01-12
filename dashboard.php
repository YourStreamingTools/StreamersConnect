<?php
session_start();

// Load configuration
require_once '/var/www/config/streamersconnect.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: https://streamersconnect.com/');
    exit;
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: https://streamersconnect.com/');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Preview - StreamersConnect</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.css">
    <link rel="stylesheet" href="custom.css?v=<?php echo filemtime(__DIR__ . '/custom.css'); ?>">
</head>
<body>
    <div class="container container-wide">
        <div class="logo"><i class="fas fa-lock"></i></div>
        <h1>StreamersConnect</h1>
        <p class="subtitle">Partner Dashboard Preview</p>
        <div style="display: flex; gap: 10px; justify-content: center; margin-bottom: 2rem;">
            <a href="/" class="btn" style="background: #667eea; padding: 0.5rem 1rem; margin: 0;"><i class="fas fa-home"></i> Home</a>
            <a href="?logout=1" class="btn btn-logout" style="margin: 0;">Logout</a>
        </div>
        <div class="info-box" style="background: #fff3cd; border-left: 4px solid #ffc107;">
            <h3 style="color: #856404;"><i class="fas fa-exclamation-triangle"></i> Preview Mode</h3>
            <p style="color: #856404;">This is a non-functional preview of the upcoming partner dashboard. All features are disabled and data shown is placeholder content.</p>
        </div>
        <div class="info-box">
            <h3><i class="fas fa-user"></i> Welcome, <?php echo htmlspecialchars($_SESSION['user_display_name']); ?>!</h3>
            <p>You're logged in with Twitch as <strong><?php echo htmlspecialchars($_SESSION['user_login']); ?></strong></p>
        </div>
        <!-- OAuth Application Management Preview -->
        <div class="info-box">
            <h3><i class="fas fa-key"></i> OAuth Applications</h3>
            <p style="margin-bottom: 1rem;">Manage your OAuth applications and credentials.</p>
            <div style="background: #f7fafc; padding: 15px; border-radius: 8px; margin-bottom: 1rem;">
                <h4 style="color: #667eea; margin-bottom: 10px; font-size: 1em;">Application #1 - Production App</h4>
                <p style="color: #4a5568; font-size: 0.9em; margin: 5px 0;"><strong>Client ID:</strong> abc123***************xyz</p>
                <p style="color: #4a5568; font-size: 0.9em; margin: 5px 0;"><strong>Redirect URLs:</strong> https://example.com/callback</p>
                <p style="color: #4a5568; font-size: 0.9em; margin: 5px 0;"><strong>Status:</strong> <span style="color: #48bb78;">Active</span></p>
                <button disabled style="margin-top: 10px; padding: 8px 15px; background: #cbd5e0; color: #718096; border: none; border-radius: 4px; cursor: not-allowed;">Edit (Coming Soon)</button>
            </div>
            <button disabled style="padding: 8px 15px; background: #cbd5e0; color: #718096; border: none; border-radius: 4px; cursor: not-allowed;"><i class="fas fa-plus"></i> Create New Application</button>
        </div>
        <!-- Analytics Preview -->
        <div class="info-box">
            <h3><i class="fas fa-chart-bar"></i> Authentication Analytics</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 1rem;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 8px; color: white; text-align: center;">
                    <div style="font-size: 2em; font-weight: bold;">1,234</div>
                    <div style="font-size: 0.9em; margin-top: 5px;">Total Auths</div>
                </div>
                <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 20px; border-radius: 8px; color: white; text-align: center;">
                    <div style="font-size: 2em; font-weight: bold;">856</div>
                    <div style="font-size: 0.9em; margin-top: 5px;">This Month</div>
                </div>
                <div style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); padding: 20px; border-radius: 8px; color: white; text-align: center;">
                    <div style="font-size: 2em; font-weight: bold;">98.5%</div>
                    <div style="font-size: 0.9em; margin-top: 5px;">Success Rate</div>
                </div>
            </div>
            <p style="margin-top: 1rem; color: #a0aec0; font-size: 0.9em;"><i class="fas fa-info-circle"></i> Real-time analytics coming soon</p>
        </div>
        <!-- Service Configuration Preview -->
        <div class="info-box">
            <h3><i class="fas fa-cog"></i> Service Configuration</h3>
            <p style="margin-bottom: 1rem;">Configure your authentication services and scopes.</p>
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; color: #4a5568; font-weight: 500;">
                    <i class="fab fa-twitch" style="color: #9147ff;"></i> Twitch Scopes
                </label>
                <input type="text" disabled value="user:read:email channel:read:subscriptions" style="width: 100%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 4px; background: #f7fafc; color: #718096;">
            </div>
            <div style="margin-bottom: 15px;">
                <label style="display: block; margin-bottom: 5px; color: #4a5568; font-weight: 500;">
                    <i class="fab fa-discord" style="color: #5865F2;"></i> Discord Scopes
                </label>
                <input type="text" disabled value="identify email guilds" style="width: 100%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 4px; background: #f7fafc; color: #718096;">
            </div>
            <button disabled style="padding: 10px 20px; background: #cbd5e0; color: #718096; border: none; border-radius: 4px; cursor: not-allowed; font-weight: 500;">Save Configuration (Coming Soon)</button>
        </div>
        <!-- Webhook Management Preview -->
        <div class="info-box">
            <h3><i class="fas fa-bell"></i> Webhook Management</h3>
            <p style="margin-bottom: 1rem;">Configure webhooks for authentication events.</p>
            <div style="background: #f7fafc; padding: 15px; border-radius: 8px;">
                <div style="margin-bottom: 10px;">
                    <label style="display: block; margin-bottom: 5px; color: #4a5568; font-weight: 500;">Webhook URL</label>
                    <input type="text" disabled placeholder="https://your-domain.com/webhook" style="width: 100%; padding: 10px; border: 1px solid #e2e8f0; border-radius: 4px; background: white; color: #718096;">
                </div>
                <div style="margin-bottom: 10px;">
                    <label style="display: block; margin-bottom: 5px; color: #4a5568; font-weight: 500;">Events</label>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        <label style="display: flex; align-items: center; gap: 5px; color: #4a5568;">
                            <input type="checkbox" disabled checked> auth.success
                        </label>
                        <label style="display: flex; align-items: center; gap: 5px; color: #4a5568;">
                            <input type="checkbox" disabled> auth.failure
                        </label>
                        <label style="display: flex; align-items: center; gap: 5px; color: #4a5568;">
                            <input type="checkbox" disabled> token.refresh
                        </label>
                    </div>
                </div>
                <button disabled style="padding: 8px 15px; background: #cbd5e0; color: #718096; border: none; border-radius: 4px; cursor: not-allowed;">Test Webhook (Coming Soon)</button>
            </div>
        </div>
        <div class="footer">
            <p>&copy; <?php echo date('Y'); ?> StreamersConnect - Part of the StreamingTools Ecosystem</p>
        </div>
    </div>
</body>
</html>
