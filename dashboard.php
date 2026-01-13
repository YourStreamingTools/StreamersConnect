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
// Check if user is whitelisted
$userLogin = $_SESSION['user_login'];
$isWhitelisted = isWhitelistedUser($userLogin);
// If whitelisted, fetch real data
$twitchScopes = 'user:read:email';
$discordScopes = 'identify email guilds';
if ($isWhitelisted) {
    $conn = getStreamersConnectDB();
    if ($conn) {
        $stmt = $conn->prepare("SELECT twitch_scopes, discord_scopes FROM user_service_config WHERE user_login = ? LIMIT 1");
        $stmt->bind_param('s', $userLogin);
        $stmt->execute();
        $stmt->bind_result($dbTwitch, $dbDiscord);
        if ($stmt->fetch()) {
            $twitchScopes = $dbTwitch ?: $twitchScopes;
            $discordScopes = $dbDiscord ?: $discordScopes;
        }
        $stmt->close();
        // AJAX save handler
        if (isset($_GET['save']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $newTwitch = trim($_POST['twitch_scopes'] ?? 'user:read:email');
            $newDiscord = trim($_POST['discord_scopes'] ?? 'identify email guilds');
            $stmt = $conn->prepare("REPLACE INTO user_service_config (user_login, twitch_scopes, discord_scopes) VALUES (?, ?, ?)");
            $stmt->bind_param('sss', $userLogin, $newTwitch, $newDiscord);
            $ok = $stmt->execute();
            $stmt->close();
            header('Content-Type: application/json');
            echo json_encode(['success' => $ok]);
            exit;
        }
    }
}
$authStats = null;
$recentAuths = null;
$domainStats = null;
if ($isWhitelisted) {
    $conn = getStreamersConnectDB();
    if ($conn) {
        // Get overall statistics
        $stmt = $conn->prepare("
            SELECT 
                COUNT(*) as total_auths,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_auths,
                SUM(CASE WHEN MONTH(created_at) = MONTH(CURRENT_DATE()) AND YEAR(created_at) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END) as this_month
            FROM auth_logs
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        $authStats = $result->fetch_assoc();
        $stmt->close();
        // Calculate success rate
        if ($authStats['total_auths'] > 0) {
            $authStats['success_rate'] = round(($authStats['successful_auths'] / $authStats['total_auths']) * 100, 1);
        } else {
            $authStats['success_rate'] = 0;
        }
        // Get authentication by domain
        $stmt = $conn->prepare("
            SELECT 
                origin_domain,
                COUNT(*) as auth_count,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                MAX(created_at) as last_auth
            FROM auth_logs
            GROUP BY origin_domain
            ORDER BY auth_count DESC
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        $domainStats = [];
        while ($row = $result->fetch_assoc()) {
            $domainStats[] = $row;
        }
        $stmt->close();
        // Get recent authentication attempts (last 10)
        $stmt = $conn->prepare("
            SELECT 
                service,
                origin_domain,
                user_login,
                user_display_name,
                success,
                error_message,
                created_at
            FROM auth_logs
            ORDER BY created_at DESC
            LIMIT 20
        ");
        $stmt->execute();
        $result = $stmt->get_result();
        $recentAuths = [];
        while ($row = $result->fetch_assoc()) {
            $recentAuths[] = $row;
        }
        $stmt->close();
    }
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
    <!-- Toastify CSS -->
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
</head>
<body>
    <div class="container container-wide">
        <div class="logo"><i class="fas fa-lock"></i></div>
        <h1>StreamersConnect</h1>
        <p class="subtitle"><?php echo $isWhitelisted ? 'Partner Dashboard' : 'Partner Dashboard Preview'; ?></p>
        <div class="center-row">
            <a href="/" class="btn btn-small bg-primary zero-margin"><i class="fas fa-home"></i> Home</a>
            <?php if ($isWhitelisted): ?>
            <a href="/stats.php" class="btn btn-small bg-success zero-margin"><i class="fas fa-chart-line"></i> Detailed Stats</a>
            <?php endif; ?>
            <a href="?logout=1" class="btn btn-logout zero-margin">Logout</a>
        </div>
        <?php if (!$isWhitelisted): ?>
        <div class="info-box alert-preview">
            <h3><i class="fas fa-exclamation-triangle"></i> Preview Mode</h3>
            <p>This is a non-functional preview of the upcoming partner dashboard. All features are disabled and data shown is placeholder content.</p>
        </div>
        <?php endif; ?>
        <div class="info-box">
            <h3><i class="fas fa-user"></i> Welcome, <?php echo htmlspecialchars($_SESSION['user_display_name']); ?>!</h3>
            <p>You're logged in with Twitch as <strong><?php echo htmlspecialchars($_SESSION['user_login']); ?></strong></p>
            <?php if ($isWhitelisted): ?>
            <p class="whitelisted-badge"><i class="fas fa-check-circle"></i> You have full dashboard access</p>
            <?php endif; ?>
        </div>
        <!-- OAuth Application Management Preview -->
        <div class="info-box">
            <h3><i class="fas fa-key"></i> OAuth Applications</h3>
            <p class="info-text-white">Manage your OAuth applications and credentials.</p>
            <div class="app-card">
                <h4>Application #1 - Production App</h4>
                <p><strong>Client ID:</strong> abc123***************xyz</p>
                <p><strong>Redirect URLs:</strong> https://example.com/callback</p>
                <p><strong>Status:</strong> <span class="status-active">Active</span></p>
                <button disabled class="btn-disabled mt-10">Edit (Coming Soon)</button>
            </div>
            <button disabled class="btn-disabled"><i class="fas fa-plus"></i> Create New Application</button>
        </div>
        <!-- Analytics -->
        <div class="info-box">
            <h3><i class="fas fa-chart-bar"></i> Authentication Analytics</h3>
            <div class="analytics-grid">
                <div class="analytics-card analytics-gradient-1">
                    <div class="analytics-value">
                        <?php echo $isWhitelisted && $authStats ? number_format($authStats['total_auths']) : '1,234'; ?>
                    </div>
                    <div class="analytics-label">Total Auths</div>
                </div>
                <div class="analytics-card analytics-gradient-2">
                    <div class="analytics-value">
                        <?php echo $isWhitelisted && $authStats ? number_format($authStats['this_month']) : '856'; ?>
                    </div>
                    <div class="analytics-label">This Month</div>
                </div>
                <div class="analytics-card analytics-gradient-3">
                    <div class="analytics-value">
                        <?php echo $isWhitelisted && $authStats ? $authStats['success_rate'] . '%' : '98.5%'; ?>
                    </div>
                    <div class="analytics-label">Success Rate</div>
                </div>
            </div>
            <?php if (!$isWhitelisted): ?>
            <p class="analytics-note"><i class="fas fa-info-circle"></i> Real-time analytics coming soon</p>
            <?php endif; ?>
        </div>
        <?php if ($isWhitelisted && $domainStats): ?>
        <!-- Domain Statistics -->
        <div class="info-box">
            <h3><i class="fas fa-globe"></i> Authentication by Domain</h3>
            <p class="info-text-white">Authentication activity across your connected domains</p>
            <div class="table-responsive">
                <table class="table-dark">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th class="center">Total Auths</th>
                            <th class="center">Success Rate</th>
                            <th>Last Auth</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($domainStats as $stat): 
                            $successRate = $stat['auth_count'] > 0 ? round(($stat['successful'] / $stat['auth_count']) * 100, 1) : 0;
                            if ($successRate >= 95) { $successClass = 'rate-high'; } elseif ($successRate >= 80) { $successClass = 'rate-medium'; } else { $successClass = 'rate-low'; }
                        ?>
                        <tr class="table-row">
                            <td>
                                <i class="fas fa-globe domain-icon"></i>
                                <strong><?php echo htmlspecialchars($stat['origin_domain']); ?></strong>
                            </td>
                            <td class="center"><strong><?php echo number_format($stat['auth_count']); ?></strong></td>
                            <td class="center"><span class="<?php echo $successClass; ?>"><?php echo $successRate; ?>%</span></td>
                            <td>
                                <?php 
                                    $lastAuth = new DateTime($stat['last_auth']);
                                    echo $lastAuth->format('M j, Y g:i A');
                                ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Recent Authentication Activity -->
        <div class="info-box">
            <h3><i class="fas fa-history"></i> Recent Authentication Activity</h3>
            <p class="info-text-white">Last 20 authentication attempts across all domains</p>
            <div class="table-responsive">
                <table class="table-dark table-sm">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Service</th>
                            <th>Domain</th>
                            <th>User</th>
                            <th class="center">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        function timeAgo($datetime) {
                            try {
                                $dt = new DateTime($datetime, new DateTimeZone('UTC'));
                                $now = new DateTime('now', new DateTimeZone('UTC'));
                                $diff = $now->getTimestamp() - $dt->getTimestamp();
                                if ($diff < 0) $diff = 0;
                                if ($diff < 60) {
                                    return $diff . 's ago';
                                } elseif ($diff < 3600) {
                                    return floor($diff / 60) . 'm ago';
                                } elseif ($diff < 86400) {
                                    return floor($diff / 3600) . 'h ago';
                                } else {
                                    return floor($diff / 86400) . 'd ago';
                                }
                            } catch (Exception $e) {
                                return 'Unknown';
                            }
                        }
                        foreach ($recentAuths as $auth):
                            $serviceLabel = '';
                            if ($auth['service'] === 'twitch') {
                                $serviceLabel = '<i class="fab fa-twitch service-twitch"></i> Twitch';
                            } elseif ($auth['service'] === 'discord') {
                                $serviceLabel = '<i class="fab fa-discord service-discord"></i> Discord';
                            } else {
                                $serviceLabel = '<i class="fas fa-question-circle"></i> ' . htmlspecialchars($auth['service']);
                            }
                        ?>
                        <tr class="table-row">
                            <td class="time-col"><span class="js-timeago" data-iso="<?php echo htmlspecialchars($auth['created_at']); ?>">...</span></td>
                            <td class="service-col"><?php echo $serviceLabel; ?></td>
                            <td class="domain-col"><?php echo htmlspecialchars($auth['origin_domain']); ?></td>
                            <td class="user-col"><?php echo htmlspecialchars($auth['user_login'] ?? 'Unknown'); ?></td>
                            <td class="status-col">
                                <?php if ($auth['success']): ?>
                                    <span class="status-success"><i class="fas fa-check-circle"></i> Success</span>
                                <?php else: ?>
                                    <span class="status-failed" title="<?php echo htmlspecialchars($auth['error_message'] ?? 'Unknown error'); ?>"><i class="fas fa-times-circle"></i> Failed</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>
        <!-- Service Configuration -->
        <div class="info-box">
            <h3><i class="fas fa-cog"></i> Service Configuration</h3>
            <p class="info-text-white">Configure your authentication services and scopes.</p>
            <?php if ($isWhitelisted): ?>
            <form id="serviceConfigForm" method="post" style="margin-bottom:0;">
                <div class="mb-15">
                    <label class="label-white"><i class="fab fa-twitch service-twitch"></i> Twitch Scopes</label>
                    <input type="text" name="twitch_scopes" id="twitch_scopes" value="<?php echo htmlspecialchars($twitchScopes); ?>" class="input-disabled" style="background:#fff;color:#1a202c;" autocomplete="off">
                </div>
                <div class="mb-15">
                    <label class="label-white"><i class="fab fa-discord service-discord"></i> Discord Scopes</label>
                    <input type="text" name="discord_scopes" id="discord_scopes" value="<?php echo htmlspecialchars($discordScopes); ?>" class="input-disabled" style="background:#fff;color:#1a202c;" autocomplete="off">
                </div>
                <button type="submit" class="btn bg-primary">Save Configuration</button>
            </form>
            <?php else: ?>
                <div class="mb-15">
                    <label class="label-white"><i class="fab fa-twitch service-twitch"></i> Twitch Scopes</label>
                    <input type="text" disabled value="user:read:email" class="input-disabled">
                </div>
                <div class="mb-15">
                    <label class="label-white"><i class="fab fa-discord service-discord"></i> Discord Scopes</label>
                    <input type="text" disabled value="identify email guilds" class="input-disabled">
                </div>
                <button disabled class="btn-disabled">Save Configuration (Coming Soon)</button>
            <?php endif; ?>
        </div>
        <!-- Webhook Management Preview -->
        <div class="info-box">
            <h3><i class="fas fa-bell"></i> Webhook Management</h3>
            <p class="info-text-white">Configure webhooks for authentication events.</p>
            <div class="app-card">
                <div class="mb-10">
                    <label class="label-white">Webhook URL</label>
                    <input type="text" disabled placeholder="https://your-domain.com/webhook" class="input-light">
                </div>
                <div class="mb-10">
                    <label class="label-white">Events</label>
                    <div class="flex-wrap-gap">
                        <label class="checkbox-label">
                            <input type="checkbox" disabled checked> auth.success
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" disabled> auth.failure
                        </label>
                        <label class="checkbox-label">
                            <input type="checkbox" disabled> token.refresh
                        </label>
                    </div>
                </div>
                <button disabled class="btn-disabled">Test Webhook (Coming Soon)</button>
            </div>
        </div>
        <div class="footer">
            <p>&copy; <?php echo date('Y'); ?> StreamersConnect - Part of the StreamingTools Ecosystem</p>
        </div>
    </div>
<script src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
<script>
// AJAX save for service config
document.addEventListener('DOMContentLoaded', function() {
    var form = document.getElementById('serviceConfigForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            var data = new FormData(form);
            fetch('?save=1', {
                method: 'POST',
                body: data
            })
            .then(r => r.json())
            .then(res => {
                Toastify({
                    text: res.success ? "Service configuration saved!" : "Save failed.",
                    duration: 3000,
                    gravity: "top",
                    position: "right",
                    backgroundColor: res.success ? "#48bb78" : "#ef4444",
                    stopOnFocus: true
                }).showToast();
            });
        });
    }
    // Display relative time using browser's timezone
    document.querySelectorAll('.js-timeago').forEach(function(el) {
        const iso = el.getAttribute('data-iso');
        if (iso) {
            el.textContent = timeAgoJS(iso);
        }
    });
});
function timeAgoJS(dateString) {
    const now = new Date();
    let then = new Date(dateString);
    if (isNaN(then.getTime())) {
        then = new Date(dateString + 'Z');
    }
    const diff = Math.floor((now - then) / 1000);
    if (isNaN(diff)) return 'Unknown';
    if (diff < 0) return '0s ago';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
}
</script>
</body>
</html>
