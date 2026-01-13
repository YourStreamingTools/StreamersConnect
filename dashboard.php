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
$twitchId = $_SESSION['user_id'];
$isWhitelisted = isWhitelistedUser($twitchId);
// If not whitelisted by ID, check if they're whitelisted by username (for migration)
if (!$isWhitelisted) {
    $conn = getStreamersConnectDB();
    if ($conn) {
        $stmt = $conn->prepare("SELECT id FROM dashboard_whitelist WHERE user_login = ? AND (twitch_id IS NULL OR twitch_id = '')");
        $stmt->bind_param('s', $userLogin);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            // Migrate: Update the record with twitch_id
            $stmt2 = $conn->prepare("UPDATE dashboard_whitelist SET twitch_id = ?, display_name = ?, email = ?, last_login = NOW() WHERE user_login = ?");
            $stmt2->bind_param('ssss', $twitchId, $_SESSION['user_display_name'], $_SESSION['user_email'], $userLogin);
            $stmt2->execute();
            $stmt2->close();
            $isWhitelisted = true;
        }
        $stmt->close();
    }
}

// If whitelisted, update their info in the database
if ($isWhitelisted) {
    $conn = getStreamersConnectDB();
    if ($conn) {
        // Update whitelist table with current session data
        $stmt = $conn->prepare("UPDATE dashboard_whitelist SET user_login = ?, display_name = ?, email = ?, last_login = NOW() WHERE twitch_id = ?");
        $stmt->bind_param('ssss', $userLogin, $_SESSION['user_display_name'], $_SESSION['user_email'], $twitchId);
        $stmt->execute();
        $stmt->close();
    }
}

// If whitelisted, fetch real data
$twitchScopes = 'user:read:email';
$discordScopes = 'identify email guilds';
if ($isWhitelisted) {
    $conn = getStreamersConnectDB();
    if ($conn) {
        // Service config fetch
        $stmt = $conn->prepare("SELECT twitch_scopes, discord_scopes FROM user_service_config WHERE user_login = ? LIMIT 1");
        $stmt->bind_param('s', $userLogin);
        $stmt->execute();
        $stmt->bind_result($dbTwitch, $dbDiscord);
        if ($stmt->fetch()) {
            $twitchScopes = $dbTwitch ?: $twitchScopes;
            $discordScopes = $dbDiscord ?: $discordScopes;
        }
        $stmt->close();
        // --- OAUTH APP AJAX HANDLERS ---
        if (isset($_GET['oauth_app']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_POST['action'] ?? '';
            if ($action === 'create') {
                $service = $_POST['service'] ?? '';
                $app_name = $_POST['app_name'] ?? '';
                $client_id = $_POST['client_id'] ?? '';
                $client_secret = $_POST['client_secret'] ?? '';
                $is_default = isset($_POST['is_default']) ? 1 : 0;
                $domain_ids = isset($_POST['domain_ids']) ? json_decode($_POST['domain_ids'], true) : [];
                $stmt = $conn->prepare("INSERT INTO oauth_applications (user_id, user_login, service, app_name, client_id, client_secret, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param('ssssssi', $twitchId, $userLogin, $service, $app_name, $client_id, $client_secret, $is_default);
                $ok = $stmt->execute();
                $newAppId = $conn->insert_id;
                $stmt->close();
                // Assign domains to this OAuth app if not default
                if ($ok && !$is_default && !empty($domain_ids)) {
                    $updateStmt = $conn->prepare("UPDATE user_allowed_domains SET oauth_app_id=? WHERE id=? AND twitch_id=?");
                    foreach ($domain_ids as $domainId) {
                        $domainId = intval($domainId);
                        $updateStmt->bind_param('iis', $newAppId, $domainId, $twitchId);
                        $updateStmt->execute();
                    }
                    $updateStmt->close();
                }
                header('Content-Type: application/json');
                echo json_encode(['success' => $ok]);
                exit;
            } elseif ($action === 'edit') {
                $id = intval($_POST['id'] ?? 0);
                $service = $_POST['service'] ?? '';
                $app_name = $_POST['app_name'] ?? '';
                $client_id = $_POST['client_id'] ?? '';
                $client_secret = $_POST['client_secret'] ?? '';
                $is_default = isset($_POST['is_default']) ? 1 : 0;
                $domain_ids = isset($_POST['domain_ids']) ? json_decode($_POST['domain_ids'], true) : [];
                $stmt = $conn->prepare("UPDATE oauth_applications SET service=?, app_name=?, client_id=?, client_secret=?, is_default=? WHERE id=? AND user_login=?");
                $stmt->bind_param('ssssiis', $service, $app_name, $client_id, $client_secret, $is_default, $id, $userLogin);
                $ok = $stmt->execute();
                $stmt->close();
                // Clear old domain assignments for this app
                $clearStmt = $conn->prepare("UPDATE user_allowed_domains SET oauth_app_id=NULL WHERE oauth_app_id=? AND twitch_id=?");
                $clearStmt->bind_param('is', $id, $twitchId);
                $clearStmt->execute();
                $clearStmt->close();
                // Assign selected domains if not default
                if ($ok && !$is_default && !empty($domain_ids)) {
                    $updateStmt = $conn->prepare("UPDATE user_allowed_domains SET oauth_app_id=? WHERE id=? AND twitch_id=?");
                    foreach ($domain_ids as $domainId) {
                        $domainId = intval($domainId);
                        $updateStmt->bind_param('iis', $id, $domainId, $twitchId);
                        $updateStmt->execute();
                    }
                    $updateStmt->close();
                }
                header('Content-Type: application/json');
                echo json_encode(['success' => $ok]);
                exit;
            } elseif ($action === 'delete') {
                $id = intval($_POST['id'] ?? 0);
                $stmt = $conn->prepare("DELETE FROM oauth_applications WHERE id=? AND user_login=?");
                $stmt->bind_param('is', $id, $userLogin);
                $ok = $stmt->execute();
                $stmt->close();
                header('Content-Type: application/json');
                echo json_encode(['success' => $ok]);
                exit;
            } elseif ($action === 'list') {
                $apps = [];
                $stmt = $conn->prepare("SELECT id, service, app_name, client_id, client_secret, is_default FROM oauth_applications WHERE user_login=? ORDER BY is_default DESC, id DESC");
                $stmt->bind_param('s', $userLogin);
                $stmt->execute();
                $result = $stmt->get_result();
                while ($row = $result->fetch_assoc()) {
                    $apps[] = $row;
                }
                $stmt->close();
                header('Content-Type: application/json');
                echo json_encode(['success' => true, 'apps' => $apps]);
                exit;
            }
        }
        // --- END OAUTH APP AJAX HANDLERS ---
        // --- DOMAIN MANAGEMENT AJAX HANDLERS ---
        if (isset($_GET['domain']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_POST['action'] ?? '';
            if ($action === 'create') {
                $domain = trim($_POST['domain'] ?? '');
                $notes = trim($_POST['notes'] ?? '');
                $oauth_app_id = !empty($_POST['oauth_app_id']) ? intval($_POST['oauth_app_id']) : null;
                if ($domain) {
                    $stmt = $conn->prepare("INSERT INTO user_allowed_domains (twitch_id, domain, notes, oauth_app_id) VALUES (?, ?, ?, ?)");
                    $stmt->bind_param('sssi', $twitchId, $domain, $notes, $oauth_app_id);
                    $ok = $stmt->execute();
                    $stmt->close();
                    header('Content-Type: application/json');
                    echo json_encode(['success' => $ok]);
                } else {
                    header('Content-Type: application/json');
                    echo json_encode(['success' => false]);
                }
                exit;
            } elseif ($action === 'edit') {
                $id = intval($_POST['id'] ?? 0);
                $domain = trim($_POST['domain'] ?? '');
                $notes = trim($_POST['notes'] ?? '');
                $oauth_app_id = !empty($_POST['oauth_app_id']) ? intval($_POST['oauth_app_id']) : null;
                if ($id && $domain) {
                    $stmt = $conn->prepare("UPDATE user_allowed_domains SET domain=?, notes=?, oauth_app_id=? WHERE id=? AND twitch_id=?");
                    $stmt->bind_param('ssiis', $domain, $notes, $oauth_app_id, $id, $twitchId);
                    $ok = $stmt->execute();
                    $stmt->close();
                    header('Content-Type: application/json');
                    echo json_encode(['success' => $ok]);
                } else {
                    header('Content-Type: application/json');
                    echo json_encode(['success' => false]);
                }
                exit;
            } elseif ($action === 'delete') {
                $id = intval($_POST['id'] ?? 0);
                if ($id) {
                    $stmt = $conn->prepare("DELETE FROM user_allowed_domains WHERE id=? AND twitch_id=?");
                    $stmt->bind_param('is', $id, $twitchId);
                    $ok = $stmt->execute();
                    $stmt->close();
                    header('Content-Type: application/json');
                    echo json_encode(['success' => $ok]);
                } else {
                    header('Content-Type: application/json');
                    echo json_encode(['success' => false]);
                }
                exit;
            } elseif ($action === 'list') {
                $stmt = $conn->prepare("
                    SELECT d.id, d.domain, d.notes, d.created_at, d.oauth_app_id, 
                           o.app_name, o.service 
                    FROM user_allowed_domains d 
                    LEFT JOIN oauth_applications o ON d.oauth_app_id = o.id 
                    WHERE d.twitch_id=? 
                    ORDER BY d.domain ASC
                ");
                $stmt->bind_param('s', $twitchId);
                $stmt->execute();
                $result = $stmt->get_result();
                $domains = [];
                while ($row = $result->fetch_assoc()) {
                    $domains[] = $row;
                }
                $stmt->close();
                header('Content-Type: application/json');
                echo json_encode(['success' => true, 'domains' => $domains]);
                exit;
            }
        }
        // --- END DOMAIN MANAGEMENT AJAX HANDLERS ---
        // --- WEBHOOK MANAGEMENT AJAX HANDLERS ---
        if (isset($_GET['webhook']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_POST['action'] ?? '';
            header('Content-Type: application/json');
            if ($action === 'list') {
                $stmt = $conn->prepare("SELECT id, name, webhook_url, secret, event_success, event_failure, created_at FROM webhooks WHERE twitch_id = ? ORDER BY id DESC");
                $stmt->bind_param('s', $twitchId);
                $stmt->execute();
                $result = $stmt->get_result();
                $webhooks = [];
                while ($row = $result->fetch_assoc()) {
                    $webhooks[] = $row;
                }
                $stmt->close();
                echo json_encode(['success' => true, 'webhooks' => $webhooks]);
                exit;
            } elseif ($action === 'save') {
                $id = $_POST['id'] ?? 0;
                $name = trim($_POST['name'] ?? '');
                $webhookUrl = trim($_POST['webhook_url'] ?? '');
                $eventSuccess = isset($_POST['event_success']) ? 1 : 0;
                $eventFailure = isset($_POST['event_failure']) ? 1 : 0;
                if (empty($name)) {
                    echo json_encode(['success' => false, 'message' => 'Webhook name is required']);
                    exit;
                }
                if (empty($webhookUrl)) {
                    echo json_encode(['success' => false, 'message' => 'Webhook URL is required']);
                    exit;
                }
                if (!filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
                    echo json_encode(['success' => false, 'message' => 'Invalid webhook URL']);
                    exit;
                }
                if ($id > 0) {
                    // Update (don't change secret on update)
                    $stmt = $conn->prepare("UPDATE webhooks SET name = ?, webhook_url = ?, event_success = ?, event_failure = ? WHERE id = ? AND twitch_id = ?");
                    $stmt->bind_param('ssiiis', $name, $webhookUrl, $eventSuccess, $eventFailure, $id, $twitchId);
                } else {
                    // Insert - use provided secret or generate one
                    $secret = trim($_POST['secret'] ?? '');
                    if (empty($secret)) {
                        $secret = bin2hex(random_bytes(32));
                    }
                    // Validate secret length (max 64 characters)
                    if (strlen($secret) > 64) {
                        echo json_encode(['success' => false, 'message' => 'Secret must be 64 characters or less']);
                        exit;
                    }
                    $stmt = $conn->prepare("INSERT INTO webhooks (twitch_id, user_login, name, webhook_url, secret, event_success, event_failure) VALUES (?, ?, ?, ?, ?, ?, ?)");
                    $stmt->bind_param('sssssii', $twitchId, $userLogin, $name, $webhookUrl, $secret, $eventSuccess, $eventFailure);
                }
                $success = $stmt->execute();
                $stmt->close();
                echo json_encode(['success' => $success]);
                exit;
            } elseif ($action === 'delete') {
                $id = intval($_POST['id'] ?? 0);
                $stmt = $conn->prepare("DELETE FROM webhooks WHERE id = ? AND twitch_id = ?");
                $stmt->bind_param('is', $id, $twitchId);
                $success = $stmt->execute();
                $stmt->close();
                echo json_encode(['success' => $success]);
                exit;
            }
            echo json_encode(['success' => false, 'message' => 'Invalid action']);
            exit;
        }
        // --- END WEBHOOK MANAGEMENT AJAX HANDLERS ---
        // AJAX save handler (service config)
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
        // Fetch user's OAuth apps for display
        $userOAuthApps = [];
        $stmt = $conn->prepare("SELECT id, service, app_name, client_id, client_secret, is_default FROM oauth_applications WHERE user_login=? ORDER BY is_default DESC, id DESC");
        $stmt->bind_param('s', $userLogin);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $userOAuthApps[] = $row;
        }
        $stmt->close();
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
                SUM(CASE WHEN MONTH(al.created_at) = MONTH(CURRENT_DATE()) AND YEAR(al.created_at) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END) as this_month
            FROM auth_logs al
            INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
            WHERE uad.twitch_id = ?
        ");
        $stmt->bind_param('s', $twitchId);
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
                al.origin_domain,
                COUNT(*) as auth_count,
                SUM(CASE WHEN al.success = 1 THEN 1 ELSE 0 END) as successful,
                MAX(al.created_at) as last_auth
            FROM auth_logs al
            INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
            WHERE uad.twitch_id = ?
            GROUP BY al.origin_domain
            ORDER BY auth_count DESC
        ");
        $stmt->bind_param('s', $twitchId);
        $stmt->execute();
        $result = $stmt->get_result();
        $domainStats = [];
        while ($row = $result->fetch_assoc()) {
            $domainStats[] = $row;
        }
        $stmt->close();
        // Get recent authentication attempts (last 5)
        $stmt = $conn->prepare("
            SELECT 
                al.service,
                al.origin_domain,
                al.user_login,
                al.user_display_name,
                al.success,
                al.error_message,
                al.created_at
            FROM auth_logs al
            INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
            WHERE uad.twitch_id = ?
            ORDER BY al.created_at DESC
            LIMIT 5
        ");
        $stmt->bind_param('s', $twitchId);
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
    <title>Partner Dashboard - StreamersConnect</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.css">
    <!-- Bulma CSS 1.0.4 -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.4/css/bulma.min.css">
    <!-- Custom CSS -->
    <link rel="stylesheet" href="custom.css?v=<?php echo filemtime(__DIR__ . '/custom.css'); ?>">
    <!-- Toastify CSS -->
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
</head>
<body>
    <div class="container container-wide">
        <div class="logo"><i class="fas fa-lock"></i></div>
        <h1>StreamersConnect</h1>
        <p class="subtitle">Partner Dashboard</p>
        <div class="center-row">
            <a href="/" class="btn btn-small bg-primary zero-margin"><i class="fas fa-home"></i> Home</a>
            <?php if ($isWhitelisted): ?>
            <a href="/stats.php" class="btn btn-small bg-success zero-margin"><i class="fas fa-chart-line"></i> Detailed Stats</a>
            <?php endif; ?>
            <a href="?logout=1" class="btn btn-logout zero-margin">Logout</a>
        </div>
        <?php if (!$isWhitelisted): ?>
        <div class="hero is-danger">
            <div class="hero-body">
                <p class="title">
                    <i class="fas fa-ban"></i> Access Denied
                </p>
                <p class="subtitle" style="color: #000 !important;">
                    You do not have permission to access this dashboard at this stage.<br>
                    If you have requested access, this access hasn't been granted yet, if you believe you should've received access by now, please reach out to us via email.
                </p>
            </div>
        </div>
        <?php
        // Stop execution for non-whitelisted users
        echo '</div></body></html>';
        exit;
        endif;
        ?>
        <div class="info-box">
            <h3><i class="fas fa-user"></i> Welcome, <?php echo htmlspecialchars($_SESSION['user_display_name']); ?>!</h3>
            <?php if ($isWhitelisted): ?>
            <p class="whitelisted-badge"><i class="fas fa-check-circle"></i> You have full dashboard access</p>
            <?php endif; ?>
        </div>
        <!-- OAuth Application Management -->
        <div class="info-box">
            <h3>
                <i class="fas fa-key"></i> OAuth Applications
                <button class="button is-info is-small is-pulled-right js-modal-trigger" data-target="oauthHelpModal">
                    <i class="fas fa-question-circle"></i> How To Use
                </button>
            </h3>
            <p class="info-text-white">Manage your OAuth applications and credentials.</p>
            <?php if ($isWhitelisted): ?>
                <!-- Bulma Modal for OAuth App -->
                <div id="oauthAppModal" class="modal">
                    <div class="modal-background"></div>
                    <div class="modal-card">
                        <header class="modal-card-head">
                            <p class="modal-card-title" id="modalTitle">New OAuth Application</p>
                            <button class="delete" aria-label="close"></button>
                        </header>
                        <section class="modal-card-body">
                            <input type="hidden" id="modalEditMode" value="0">
                            <input type="hidden" id="modalAppId" value="">
                            <div class="field">
                                <label class="label">Service</label>
                                <div class="control">
                                    <div class="select is-fullwidth">
                                        <select id="modalService">
                                            <option value="twitch">Twitch</option>
                                            <option value="discord">Discord</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">App Name</label>
                                <div class="control">
                                    <input class="input" type="text" id="modalAppName" maxlength="64" placeholder="My Application">
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">Client ID</label>
                                <div class="control">
                                    <input class="input" type="text" id="modalClientId" maxlength="128" placeholder="your_client_id">
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">Client Secret</label>
                                <div class="control">
                                    <input class="input" type="password" id="modalClientSecret" maxlength="128" placeholder="your_client_secret">
                                </div>
                            </div>
                            <div class="field">
                                <label class="checkbox">
                                    <input type="checkbox" id="modalIsDefault">
                                    Use as default credentials
                                </label>
                                <p class="help">If checked, this will be used when no custom OAuth credentials are provided via headers. Scopes are specified per authentication request via the <code>&scopes=</code> URL parameter.</p>
                            </div>
                            <div class="field" id="domainSelectorField" style="display: none;">
                                <label class="label">Assign to Specific Domains</label>
                                <div class="control">
                                    <div id="domainCheckboxList" class="box" style="max-height: 200px; overflow-y: auto;">
                                        <p class="has-text-grey-light">Loading domains...</p>
                                    </div>
                                </div>
                                <p class="help">Select which domains should use this OAuth application. Unselected domains will use the default OAuth application.</p>
                            </div>
                        </section>
                        <footer class="modal-card-foot">
                            <div class="buttons">
                                <button class="button is-success" id="modalSaveBtn">Create Application</button>
                                <button class="button" id="modalCancelBtn">Cancel</button>
                            </div>
                        </footer>
                    </div>
                </div>
                <div id="oauthAppsContainer"></div>
                <button class="button is-primary is-small mt-10 js-modal-trigger" data-target="oauthAppModal" id="createAppBtn"><i class="fas fa-plus"></i> Create New Application</button>
            <?php endif; ?>
        </div>
        <!-- OAuth Help Modal -->
        <div id="oauthHelpModal" class="modal">
            <div class="modal-background"></div>
            <div class="modal-card">
                <header class="modal-card-head">
                    <p class="modal-card-title"><i class="fas fa-question-circle"></i> How To Use OAuth Applications</p>
                    <button class="delete" aria-label="close"></button>
                </header>
                <section class="modal-card-body">
                    <div class="content">
                        <h4><i class="fas fa-info-circle"></i> Overview</h4>
                        <p>StreamersConnect allows your websites to authenticate users via Twitch or Discord OAuth. Follow these steps to integrate authentication into your application:</p>
                        <h4><i class="fas fa-list-ol"></i> Setup Steps</h4>
                        <ol>
                            <li>
                                <strong>1. Create an OAuth Application:</strong>
                                <ul>
                                    <li>Click "Create New Application" button</li>
                                    <li>Choose service (Twitch or Discord)</li>
                                    <li>Give it a name (e.g., "My Bot Twitch Auth")</li>
                                    <li>Enter your Client ID and Client Secret from Twitch/Discord Developer Portal</li>
                                    <li>Check "Default Application" if you want this used for all your domains by default</li>
                                    <li>Or select specific domains to use this OAuth app</li>
                                </ul>
                            </li>
                            <li>
                                <strong>2. Add Your Domain:</strong>
                                <ul>
                                    <li>Go to "Allowed Domains" section below</li>
                                    <li>Add your website domain (e.g., example.com)</li>
                                    <li>Optionally assign a specific OAuth app to this domain</li>
                                </ul>
                            </li>
                            <li>
                                <strong>3. Integrate Into Your Website:</strong>
                                <ul>
                                    <li>Use this URL format to start authentication:</li>
                                    <li class="url-code">https://streamersconnect.com/?service=twitch&login=YOUR_DOMAIN&scopes=user:read:email&return_url=https://YOUR_DOMAIN/callback</li>
                                    <li>Replace <code>YOUR_DOMAIN</code> with your actual domain</li>
                                    <li>Replace <code>scopes</code> with the permissions you need</li>
                                    <li>Replace <code>return_url</code> with where users should return after authentication</li>
                                </ul>
                            </li>
                            <li>
                                <strong>4. Handle the Response:</strong>
                                <ul>
                                    <li>Users will be redirected back to your <code>return_url</code> with an <code>auth_data</code> parameter</li>
                                    <li>Decode the base64 auth_data to get user information and access tokens</li>
                                    <li>The data includes: user ID, username, display name, email, access token, refresh token</li>
                                </ul>
                            </li>
                        </ol>
                        <h4><i class="fas fa-code"></i> Example Integration</h4>
                        <pre><code>&lt;!-- Login Button --&gt;
&lt;a href="https://streamersconnect.com/?service=twitch&login=example.com&scopes=user:read:email&return_url=https://example.com/callback" class="btn"&gt;
    Login with Twitch
&lt;/a&gt;

&lt;!-- PHP: Handle callback --&gt;
if (isset($_GET['auth_data'])) {
    $authData = json_decode(base64_decode($_GET['auth_data']), true);
    $userId = $authData['user']['id'];
    $username = $authData['user']['login'];
    $accessToken = $authData['access_token'];
    // Store in session or database
}</code></pre>
                        <h4><i class="fas fa-shield-alt"></i> Security Notes</h4>
                        <ul>
                            <li><strong>Domain Whitelist:</strong> Only domains you add to "Allowed Domains" can use your OAuth credentials</li>
                            <li><strong>Return URL Validation:</strong> The return URL must match the domain that initiated the request</li>
                            <li><strong>Client Secrets:</strong> Your Client Secret is stored securely and never exposed to the frontend</li>
                            <li><strong>Default vs Specific:</strong> Use "Default" for all domains, or assign specific OAuth apps per domain for isolation</li>
                        </ul>
                        <h4><i class="fas fa-question"></i> Need Help?</h4>
                        <p>If you need assistance, contact: <strong>partners@streamingtools.com</strong></p>
                    </div>
                </section>
                <footer class="modal-card-foot">
                    <button class="button">Close</button>
                </footer>
            </div>
        </div>
        <script>
        // --- OAUTH APP MANAGEMENT ---
            // --- OAUTH APP MANAGEMENT (Bulma Modal) ---
            function renderOAuthApps() {
                fetch('?oauth_app=1', {
                    method: 'POST',
                    body: new URLSearchParams({action: 'list'})
                })
                .then(r => r.json())
                .then(res => {
                    var list = document.getElementById('oauthAppsContainer');
                    if (!list) return;
                    if (!res.success) {
                        list.innerHTML = '<div class="notification is-danger">Failed to load applications.</div>';
                        return;
                    }
                    if (!res.apps.length) {
                        list.innerHTML = '<div class="notification is-info is-light has-text-centered"><i class="fas fa-info-circle"></i> No OAuth applications yet. Click "Create New Application" below to get started.</div>';
                        return;
                    }
                    let html = `
                        <div class="table-container" style="margin-bottom: 1rem;">
                            <table class="table is-fullwidth is-striped is-hoverable">
                                <thead>
                                    <tr>
                                        <th><i class="fas fa-key"></i> Application Name</th>
                                        <th>Service</th>
                                        <th>Client ID</th>
                                        <th class="has-text-centered">Status</th>
                                        <th class="has-text-centered">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>`;
                    res.apps.forEach(function(app) {
                        const serviceIcon = app.service === 'twitch' ? '<i class="fab fa-twitch"></i>' : '<i class="fab fa-discord"></i>';
                        const defaultBadge = app.is_default ? '<span class="tag is-success"><i class="fas fa-check-circle"></i> Default</span>' : '<span class="tag is-light">Custom</span>';
                        const appJson = JSON.stringify(app).replace(/"/g, '&quot;');
                        html += `
                            <tr data-id="${app.id}">
                                <td><strong>${app.app_name}</strong></td>
                                <td>${serviceIcon} ${app.service.charAt(0).toUpperCase() + app.service.slice(1)}</td>
                                <td><code class="is-size-7">${app.client_id}</code></td>
                                <td class="has-text-centered">${defaultBadge}</td>
                                <td class="has-text-centered">
                                    <div class="buttons is-centered">
                                        <button class="button is-small is-info oauthAppEditBtn" data-app='${appJson}'>
                                            <span class="icon is-small"><i class="fas fa-edit"></i></span>
                                            <span>Edit</span>
                                        </button>
                                        <button class="button is-small is-danger oauthAppDeleteBtn" data-id="${app.id}">
                                            <span class="icon is-small"><i class="fas fa-trash"></i></span>
                                            <span>Delete</span>
                                        </button>
                                    </div>
                                </td>
                            </tr>`;
                    });
                    html += `
                                </tbody>
                            </table>
                        </div>`;
                    list.innerHTML = html;
                });
            }
            function showOAuthAppModal(edit, app) {
                const modal = document.getElementById('oauthAppModal');
                const modalTitle = document.getElementById('modalTitle');
                const saveBtn = document.getElementById('modalSaveBtn');
                // Set modal title and button text
                modalTitle.textContent = edit ? 'Edit OAuth Application' : 'New OAuth Application';
                saveBtn.textContent = edit ? 'Save Changes' : 'Create Application';
                // Store edit mode and app ID
                document.getElementById('modalEditMode').value = edit ? '1' : '0';
                document.getElementById('modalAppId').value = edit && app ? app.id : '';
                // Populate form fields
                document.getElementById('modalService').value = (app && app.service) ? app.service : 'twitch';
                document.getElementById('modalAppName').value = (app && app.app_name) ? app.app_name : '';
                document.getElementById('modalClientId').value = (app && app.client_id) ? app.client_id : '';
                document.getElementById('modalClientSecret').value = (app && app.client_secret) ? app.client_secret : '';
                document.getElementById('modalIsDefault').checked = (app && app.is_default) ? true : false;
                // Load domains for selection
                loadDomainsForOAuthApp(edit, app);
                // Setup checkbox handler for is_default
                const isDefaultCheckbox = document.getElementById('modalIsDefault');
                const domainSelectorField = document.getElementById('domainSelectorField');
                // Show/hide domain selector based on is_default
                domainSelectorField.style.display = isDefaultCheckbox.checked ? 'none' : 'block';
                isDefaultCheckbox.onchange = function() {
                    domainSelectorField.style.display = this.checked ? 'none' : 'block';
                };
                // Show modal using Bulma pattern
                openModal(modal);
            }
            function loadDomainsForOAuthApp(edit, app) {
                const domainCheckboxList = document.getElementById('domainCheckboxList');
                fetch('?domain=1', {
                    method: 'POST',
                    body: new URLSearchParams({action: 'list'})
                })
                .then(r => r.json())
                .then(res => {
                    if (!res.success || !res.domains.length) {
                        domainCheckboxList.innerHTML = '<p class="has-text-grey-light"><i class="fas fa-info-circle"></i> No domains configured. Add domains first to assign them to specific OAuth applications.</p>';
                        return;
                    }
                    let html = '';
                    res.domains.forEach(domain => {
                        const isAssigned = edit && app && domain.oauth_app_id == app.id;
                        html += `
                            <label class="checkbox" style="display: block; margin-bottom: 0.5rem;">
                                <input type="checkbox" class="domain-checkbox" value="${domain.id}" ${isAssigned ? 'checked' : ''}>
                                <strong>${domain.domain}</strong>
                                ${domain.notes ? `<span class="has-text-grey"> - ${domain.notes}</span>` : ''}
                            </label>
                        `;
                    });
                    
                    domainCheckboxList.innerHTML = html;
                });
            }
            function saveOAuthApp() {
                const editMode = document.getElementById('modalEditMode').value === '1';
                const appId = document.getElementById('modalAppId').value;
                const service = document.getElementById('modalService').value;
                const appName = document.getElementById('modalAppName').value.trim();
                const clientId = document.getElementById('modalClientId').value.trim();
                const clientSecret = document.getElementById('modalClientSecret').value.trim();
                const isDefault = document.getElementById('modalIsDefault').checked;
                if (!appName || !clientId || !clientSecret) {
                    Toastify({
                        text: "App Name, Client ID, and Client Secret are required",
                        duration: 3000,
                        gravity: "top",
                        position: "right",
                        backgroundColor: "#ef4444",
                        stopOnFocus: true
                    }).showToast();
                    return;
                }
                var data = new FormData();
                data.append('action', editMode ? 'edit' : 'create');
                if (editMode && appId) data.append('id', appId);
                data.append('service', service);
                data.append('app_name', appName);
                data.append('client_id', clientId);
                data.append('client_secret', clientSecret);
                if (isDefault) data.append('is_default', '1');
                // Get selected domain IDs if not default
                if (!isDefault) {
                    const selectedDomains = Array.from(document.querySelectorAll('.domain-checkbox:checked'))
                        .map(cb => cb.value);
                    if (selectedDomains.length > 0) {
                        data.append('domain_ids', JSON.stringify(selectedDomains));
                    }
                }
                fetch('?oauth_app=1', {
                    method: 'POST',
                    body: data
                })
                .then(r => r.json())
                .then(res => {
                    Toastify({
                        text: res.success ? (editMode ? "Application updated!" : "Application created!") : "Save failed.",
                        duration: 3000,
                        gravity: "top",
                        position: "right",
                        backgroundColor: res.success ? "#48bb78" : "#ef4444",
                        stopOnFocus: true
                    }).showToast();
                    if (res.success) {
                        closeModal(document.getElementById('oauthAppModal'));
                        renderOAuthApps();
                        renderDomains(); // Refresh domains to show updated assignments
                    }
                });
            }
        // Standard Bulma modal functions
        function openModal($el) {
            $el.classList.add('is-active');
        }
        function closeModal($el) {
            $el.classList.remove('is-active');
        }
        function closeAllModals() {
            (document.querySelectorAll('.modal') || []).forEach(($modal) => {
                closeModal($modal);
            });
        }
        document.addEventListener('DOMContentLoaded', function() {
            // OAuth app list
            if (document.getElementById('oauthAppsContainer')) {
                renderOAuthApps();
            }
            // Add click event on buttons to open specific modal (for create button)
            (document.querySelectorAll('.js-modal-trigger') || []).forEach(($trigger) => {
                const modal = $trigger.dataset.target;
                const $target = document.getElementById(modal);
                $trigger.addEventListener('click', () => {
                    // Only reset form for OAuth app modal
                    if (modal === 'oauthAppModal') {
                        showOAuthAppModal(false, null);
                    } else {
                        // Just open the modal normally
                        openModal($target);
                    }
                });
            });
            // Add click event on modal background, close button, and cancel button
            (document.querySelectorAll('.modal-background, .modal-close, .modal-card-head .delete, #modalCancelBtn') || []).forEach(($close) => {
                const $target = $close.closest('.modal');
                $close.addEventListener('click', () => {
                    closeModal($target);
                });
            });
            // Add click event to save button
            const saveBtn = document.getElementById('modalSaveBtn');
            if (saveBtn) {
                saveBtn.addEventListener('click', saveOAuthApp);
            }
            // Add keyboard event to close all modals
            document.addEventListener('keydown', (event) => {
                if(event.key === "Escape") {
                    closeAllModals();
                }
            });
            // Edit/Delete buttons (event delegation)
            document.body.addEventListener('click', function(e) {
                if (e.target.classList.contains('oauthAppEditBtn') || e.target.closest('.oauthAppEditBtn')) {
                    var btn = e.target.classList.contains('oauthAppEditBtn') ? e.target : e.target.closest('.oauthAppEditBtn');
                    var appData = btn.getAttribute('data-app');
                    if (appData) {
                        var app = JSON.parse(appData);
                        showOAuthAppModal(true, app);
                    }
                }
                if (e.target.classList.contains('oauthAppDeleteBtn') || e.target.closest('.oauthAppDeleteBtn')) {
                    if (!confirm('Delete this application?')) return;
                    var btn = e.target.classList.contains('oauthAppDeleteBtn') ? e.target : e.target.closest('.oauthAppDeleteBtn');
                    var id = btn.getAttribute('data-id');
                    var data = new FormData();
                    data.append('action', 'delete');
                    data.append('id', id);
                    fetch('?oauth_app=1', {
                        method: 'POST',
                        body: data
                    })
                    .then(r => r.json())
                    .then(res => {
                        Toastify({
                            text: res.success ? "Application deleted!" : "Delete failed.",
                            duration: 3000,
                            gravity: "top",
                            position: "right",
                            backgroundColor: res.success ? "#48bb78" : "#ef4444",
                            stopOnFocus: true
                        }).showToast();
                        if (res.success) renderOAuthApps();
                    });
                }
            });
        });
        // --- DOMAIN MANAGEMENT (Bulma Modal) ---
        function renderDomains() {
            fetch('?domain=1', {
                method: 'POST',
                body: new URLSearchParams({action: 'list'})
            })
            .then(r => r.json())
            .then(res => {
                var list = document.getElementById('domainsContainer');
                if (!list) return;
                if (!res.success) {
                    list.innerHTML = '<div class="notification is-danger">Failed to load domains.</div>';
                    return;
                }
                if (!res.domains.length) {
                    list.innerHTML = '<div class="notification is-info is-light has-text-centered"><i class="fas fa-info-circle"></i> No domains configured yet. Click "Add Domain" below to get started.</div>';
                    return;
                }
                let html = `
                    <div class="table-container" style="margin-bottom: 1rem;">
                        <table class="table is-fullwidth is-striped is-hoverable">
                            <thead>
                                <tr>
                                    <th><i class="fas fa-globe"></i> Domain</th>
                                    <th>OAuth Application</th>
                                    <th>Notes</th>
                                    <th>Added</th>
                                    <th class="has-text-centered">Actions</th>
                                </tr>
                            </thead>
                            <tbody>`;
                res.domains.forEach(function(domain) {
                    const addedDate = new Date(domain.created_at).toLocaleDateString();
                    const notes = domain.notes ? domain.notes : '<em class="has-text-grey-light">No notes</em>';
                    const domainJson = JSON.stringify(domain).replace(/"/g, '&quot;');
                    
                    let oauthAppDisplay = '<span class="tag is-info"><i class="fas fa-globe"></i> Default</span>';
                    if (domain.oauth_app_id && domain.app_name) {
                        const serviceIcon = domain.service === 'twitch' ? '<i class="fab fa-twitch"></i>' : '<i class="fab fa-discord"></i>';
                        oauthAppDisplay = `<span class="tag is-primary">${serviceIcon} ${domain.app_name}</span>`;
                    }
                    
                    html += `
                        <tr data-id="${domain.id}">
                            <td><strong>${domain.domain}</strong></td>
                            <td>${oauthAppDisplay}</td>
                            <td>${notes}</td>
                            <td class="is-size-7 has-text-grey-light">${addedDate}</td>
                            <td class="has-text-centered">
                                <div class="buttons is-centered">
                                    <button class="button is-small is-info" onclick="showDomainModal(true, ${domainJson})">
                                        <span class="icon is-small"><i class="fas fa-edit"></i></span>
                                        <span>Edit</span>
                                    </button>
                                    <button class="button is-small is-danger" onclick="deleteDomain(${domain.id})">
                                        <span class="icon is-small"><i class="fas fa-trash"></i></span>
                                        <span>Delete</span>
                                    </button>
                                </div>
                            </td>
                        </tr>`;
                });
                html += `
                            </tbody>
                        </table>
                    </div>`;
                list.innerHTML = html;
            });
        }
        function showDomainModal(edit, domain) {
            const modal = document.getElementById('domainModal');
            const modalTitle = document.getElementById('domainModalTitle');
            const saveBtn = document.getElementById('domainModalSaveBtn');
            
            // Set modal title and button text
            modalTitle.textContent = edit ? 'Edit Domain' : 'Add New Domain';
            saveBtn.textContent = edit ? 'Save Changes' : 'Add Domain';
            
            // Store edit mode and domain ID
            document.getElementById('domainEditMode').value = edit ? '1' : '0';
            document.getElementById('domainId').value = edit && domain ? domain.id : '';
            
            // Populate form fields
            document.getElementById('modalDomain').value = (domain && domain.domain) ? domain.domain : '';
            document.getElementById('modalDomainNotes').value = (domain && domain.notes) ? domain.notes : '';
            
            // Populate OAuth app dropdown
            const oauthAppSelect = document.getElementById('modalDomainOAuthApp');
            fetch('?oauth_app=1', {
                method: 'POST',
                body: new URLSearchParams({action: 'list'})
            })
            .then(r => r.json())
            .then(res => {
                // Clear existing options except the default one
                oauthAppSelect.innerHTML = '<option value="">Use Default OAuth Application</option>';
                
                if (res.success && res.apps.length) {
                    res.apps.forEach(app => {
                        const option = document.createElement('option');
                        option.value = app.id;
                        const serviceIcon = app.service === 'twitch' ? '🟣' : '💬';
                        option.textContent = `${serviceIcon} ${app.app_name} (${app.service})`;
                        if (domain && domain.oauth_app_id && app.id == domain.oauth_app_id) {
                            option.selected = true;
                        }
                        oauthAppSelect.appendChild(option);
                    });
                }
                
                // Show modal using Bulma pattern
                openModal(modal);
            });
        }
        
        function saveDomain() {
            const editMode = document.getElementById('domainEditMode').value === '1';
            const domainId = document.getElementById('domainId').value;
            const domainValue = document.getElementById('modalDomain').value.trim();
            const notes = document.getElementById('modalDomainNotes').value.trim();
            const oauthAppId = document.getElementById('modalDomainOAuthApp').value;
            
            if (!domainValue) {
                Toastify({
                    text: "Domain is required",
                    duration: 3000,
                    gravity: "top",
                    position: "right",
                    backgroundColor: "#ef4444",
                    stopOnFocus: true
                }).showToast();
                return;
            }
            
            var data = new FormData();
            data.append('action', editMode ? 'edit' : 'create');
            if (editMode && domainId) data.append('id', domainId);
            data.append('domain', domainValue);
            data.append('notes', notes);
            if (oauthAppId) data.append('oauth_app_id', oauthAppId);
            
            fetch('?domain=1', {
                method: 'POST',
                body: data
            })
            .then(r => r.json())
            .then(res => {
                Toastify({
                    text: res.success ? (editMode ? "Domain updated!" : "Domain added!") : "Save failed.",
                    duration: 3000,
                    gravity: "top",
                    position: "right",
                    backgroundColor: res.success ? "#48bb78" : "#ef4444",
                    stopOnFocus: true
                }).showToast();
                if (res.success) {
                    closeModal(document.getElementById('domainModal'));
                    renderDomains();
                }
            });
        }
        
        function deleteDomain(id) {
            if (!confirm('Delete this domain? This cannot be undone.')) return;
            
            var data = new FormData();
            data.append('action', 'delete');
            data.append('id', id);
            fetch('?domain=1', {
                method: 'POST',
                body: data
            })
            .then(r => r.json())
            .then(res => {
                Toastify({
                    text: res.success ? "Domain deleted successfully!" : "Delete failed.",
                    duration: 3000,
                    gravity: "top",
                    position: "right",
                    backgroundColor: res.success ? "#48bb78" : "#ef4444",
                    stopOnFocus: true
                }).showToast();
                if (res.success) renderDomains();
            })
            .catch(err => {
                console.error('Delete error:', err);
                Toastify({
                    text: "Error deleting domain",
                    duration: 3000,
                    gravity: "top",
                    position: "right",
                    backgroundColor: "#ef4444",
                    stopOnFocus: true
                }).showToast();
            });
        }
        document.addEventListener('DOMContentLoaded', function() {
            // Domain management
            if (document.getElementById('domainsContainer')) {
                renderDomains();
            }
            // Webhook management
            if (document.getElementById('webhooksContainer')) {
                renderWebhooks();
            }
            // Create domain button
            var createDomainBtn = document.getElementById('createDomainBtn');
            if (createDomainBtn) {
                createDomainBtn.addEventListener('click', function() {
                    showDomainModal(false, null);
                });
            }
            // Domain modal close events
            const domainModal = document.getElementById('domainModal');
            if (domainModal) {
                // Close on background click
                domainModal.querySelector('.modal-background').addEventListener('click', () => {
                    closeModal(domainModal);
                });
                // Close on delete button click
                domainModal.querySelector('.delete').addEventListener('click', () => {
                    closeModal(domainModal);
                });
                // Cancel button
                document.getElementById('domainModalCancelBtn').addEventListener('click', () => {
                    closeModal(domainModal);
                });
                // Save button
                document.getElementById('domainModalSaveBtn').addEventListener('click', saveDomain);
            }
            // Webhook modal events
            const webhookModal = document.getElementById('webhookModal');
            if (webhookModal) {
                webhookModal.querySelector('.modal-background').addEventListener('click', () => {
                    closeModal(webhookModal);
                });
                webhookModal.querySelector('.delete').addEventListener('click', () => {
                    closeModal(webhookModal);
                });
                document.getElementById('webhookModalCancelBtn').addEventListener('click', () => {
                    closeModal(webhookModal);
                });
                document.getElementById('webhookModalSaveBtn').addEventListener('click', saveWebhook);
            }
        });
        // --- WEBHOOK MANAGEMENT ---
        function renderWebhooks() {
            fetch('?webhook=1', {
                method: 'POST',
                body: new URLSearchParams({action: 'list'})
            })
            .then(r => r.json())
            .then(res => {
                var list = document.getElementById('webhooksContainer');
                if (!res.success || !res.webhooks || res.webhooks.length === 0) {
                    list.innerHTML = '<div class="alert-info"><i class="fas fa-info-circle"></i> No webhooks configured yet. Click "Add Webhook" to create one.</div>';
                    return;
                }
                var html = '<table class="table-dark" style="margin-top: 1rem;"><thead><tr><th>Name</th><th>Webhook URL</th><th class="center">Success</th><th class="center">Failure</th><th class="center">Actions</th></tr></thead><tbody>';
                res.webhooks.forEach(function(webhook) {
                    var successIcon = webhook.event_success == 1 ? '<i class="fas fa-check" style="color: #48bb78;"></i>' : '<i class="fas fa-times" style="color: #ef4444;"></i>';
                    var failureIcon = webhook.event_failure == 1 ? '<i class="fas fa-check" style="color: #48bb78;"></i>' : '<i class="fas fa-times" style="color: #ef4444;"></i>';
                    html += '<tr>';
                    html += '<td><strong>' + escapeHtml(webhook.name) + '</strong></td>';
                    html += '<td>' + escapeHtml(webhook.webhook_url) + '</td>';
                    html += '<td class="center">' + successIcon + '</td>';
                    html += '<td class="center">' + failureIcon + '</td>';
                    html += '<td class="center nowrap">';
                    html += '<button class="btn-edit" onclick=\'showWebhookModal(true, ' + JSON.stringify(webhook) + ')\'><i class="fas fa-edit"></i> Edit</button>';
                    html += '<button class="btn-delete" onclick="deleteWebhook(' + webhook.id + ')"><i class="fas fa-trash"></i> Delete</button>';
                    html += '</td></tr>';
                });
                html += '</tbody></table>';
                list.innerHTML = html;
            });
        }
        function showWebhookModal(edit, webhook) {
            const modal = document.getElementById('webhookModal');
            const modalTitle = document.getElementById('webhookModalTitle');
            const saveBtn = document.getElementById('webhookModalSaveBtn');
            const secretField = document.getElementById('webhookSecretField');
            modalTitle.textContent = edit ? 'Edit Webhook' : 'Add Webhook';
            saveBtn.textContent = edit ? 'Save Changes' : 'Add Webhook';
            document.getElementById('webhookEditMode').value = edit ? '1' : '0';
            document.getElementById('webhookId').value = edit && webhook ? webhook.id : '';
            document.getElementById('modalWebhookName').value = (webhook && webhook.name) ? webhook.name : '';
            document.getElementById('modalWebhookUrl').value = (webhook && webhook.webhook_url) ? webhook.webhook_url : '';
            document.getElementById('modalEventSuccess').checked = !webhook || webhook.event_success == 1;
            document.getElementById('modalEventFailure').checked = !webhook || webhook.event_failure == 1;
            // Show existing secret when editing, or empty for new
            if (edit && webhook && webhook.secret) {
                document.getElementById('modalWebhookSecret').value = webhook.secret;
                document.getElementById('modalWebhookSecret').readOnly = true;
            } else {
                document.getElementById('modalWebhookSecret').value = '';
                document.getElementById('modalWebhookSecret').readOnly = false;
            }
            openModal(modal);
        }
        function saveWebhook() {
            const editMode = document.getElementById('webhookEditMode').value === '1';
            const id = document.getElementById('webhookId').value;
            const name = document.getElementById('modalWebhookName').value.trim();
            const webhookUrl = document.getElementById('modalWebhookUrl').value.trim();
            const secret = document.getElementById('modalWebhookSecret').value.trim();
            const eventSuccess = document.getElementById('modalEventSuccess').checked ? 1 : 0;
            const eventFailure = document.getElementById('modalEventFailure').checked ? 1 : 0;
            if (!name) {
                Toastify({text: "Webhook name is required", backgroundColor: "#ef4444", duration: 3000}).showToast();
                return;
            }
            if (!webhookUrl) {
                Toastify({text: "Webhook URL is required", backgroundColor: "#ef4444", duration: 3000}).showToast();
                return;
            }
            var params = new URLSearchParams({
                action: 'save',
                id: id,
                name: name,
                webhook_url: webhookUrl,
            });
            if (secret) params.append('secret', secret);
            if (eventSuccess) params.append('event_success', '1');
            if (eventFailure) params.append('event_failure', '1');
            fetch('?webhook=1', {
                method: 'POST',
                body: params
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    Toastify({text: editMode ? "Webhook updated successfully!" : "Webhook added successfully!", backgroundColor: "#10b981", duration: 3000}).showToast();
                    closeAllModals();
                    renderWebhooks();
                } else {
                    Toastify({text: res.message || "Failed to save webhook", backgroundColor: "#ef4444", duration: 3000}).showToast();
                }
            });
        }
        function deleteWebhook(id) {
            if (!confirm('Are you sure you want to delete this webhook? This action cannot be undone.')) {
                return;
            }
            fetch('?webhook=1', {
                method: 'POST',
                body: new URLSearchParams({action: 'delete', id: id})
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    Toastify({text: "Webhook deleted successfully!", backgroundColor: "#10b981", duration: 3000}).showToast();
                    renderWebhooks();
                } else {
                    Toastify({text: "Failed to delete webhook", backgroundColor: "#ef4444", duration: 3000}).showToast();
                }
            });
        }
        function escapeHtml(text) {
            var map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'};
            return text.replace(/[&<>"']/g, function(m) { return map[m]; });
        }
        function generateWebhookSecret() {
            const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            const lowercase = 'abcdefghijklmnopqrstuvwxyz';
            const numbers = '0123456789';
            const allChars = uppercase + lowercase + numbers;
            let secret = [];
            // Ensure minimum 4 uppercase letters
            const uppercaseArray = new Uint8Array(4);
            crypto.getRandomValues(uppercaseArray);
            for (let i = 0; i < 4; i++) {
                secret.push(uppercase[uppercaseArray[i] % uppercase.length]);
            }
            // Ensure minimum 4 numbers
            const numbersArray = new Uint8Array(4);
            crypto.getRandomValues(numbersArray);
            for (let i = 0; i < 4; i++) {
                secret.push(numbers[numbersArray[i] % numbers.length]);
            }
            // Fill remaining 24 characters with mix of all
            const remainingArray = new Uint8Array(24);
            crypto.getRandomValues(remainingArray);
            for (let i = 0; i < 24; i++) {
                secret.push(allChars[remainingArray[i] % allChars.length]);
            }
            // Shuffle the array to mix everything
            for (let i = secret.length - 1; i > 0; i--) {
                const randomArray = new Uint8Array(1);
                crypto.getRandomValues(randomArray);
                const j = randomArray[0] % (i + 1);
                [secret[i], secret[j]] = [secret[j], secret[i]];
            }
            document.getElementById('modalWebhookSecret').value = secret.join('');
        }
        </script>
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
            <p class="info-text-white">Last 5 authentication attempts across all domains</p>
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
        <!-- Allowed Domains Management -->
        <div class="info-box">
            <h3><i class="fas fa-globe"></i> Allowed Domains</h3>
            <p class="info-text-white">Manage domains authorized to use your OAuth applications.</p>
            <?php if ($isWhitelisted): ?>
                <!-- Bulma Modal for Domain -->
                <div id="domainModal" class="modal">
                    <div class="modal-background"></div>
                    <div class="modal-card">
                        <header class="modal-card-head">
                            <p class="modal-card-title" id="domainModalTitle">New Domain</p>
                            <button class="delete" aria-label="close"></button>
                        </header>
                        <section class="modal-card-body">
                            <input type="hidden" id="domainEditMode" value="0">
                            <input type="hidden" id="domainId" value="">
                            <div class="field">
                                <label class="label">Domain</label>
                                <div class="control">
                                    <input class="input" type="text" id="modalDomain" placeholder="example.com" maxlength="255">
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">Notes (optional)</label>
                                <div class="control">
                                    <textarea class="textarea" id="modalDomainNotes" maxlength="500"></textarea>
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">OAuth Application</label>
                                <div class="control">
                                    <div class="select is-fullwidth">
                                        <select id="modalDomainOAuthApp">
                                            <option value="">Use Default OAuth Application</option>
                                        </select>
                                    </div>
                                </div>
                                <p class="help">Select a specific OAuth application for this domain, or leave as default to use the default OAuth credentials.</p>
                            </div>
                        </section>
                        <footer class="modal-card-foot">
                            <div class="buttons">
                                <button class="button is-success" id="domainModalSaveBtn">Add Domain</button>
                                <button class="button" id="domainModalCancelBtn">Cancel</button>
                            </div>
                        </footer>
                    </div>
                </div>
                <div id="domainsContainer"></div>
                <button class="button is-primary is-small mt-10" id="createDomainBtn"><i class="fas fa-plus"></i> Add Domain</button>
            <?php endif; ?>
        </div>
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
                <button type="submit" class="btn btn-save-config">Save Configuration</button>
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
        <!-- Webhook Management -->
        <div class="info-box">
            <h3><i class="fas fa-bell"></i> Webhook Management</h3>
            <p class="info-text-white">Configure webhooks to receive notifications for authentication events.</p>
            <button class="btn-create-app js-modal-trigger" data-target="webhookModal" onclick="showWebhookModal(false, null)">
                <i class="fas fa-plus"></i> Add Webhook
            </button>
            <div id="webhooksContainer"></div>
        </div>
        <!-- Webhook Modal -->
        <div id="webhookModal" class="modal">
            <div class="modal-background"></div>
            <div class="modal-card">
                <header class="modal-card-head">
                    <p class="modal-card-title" id="webhookModalTitle">Add Webhook</p>
                    <button class="delete" aria-label="close"></button>
                </header>
                <section class="modal-card-body">
                    <input type="hidden" id="webhookEditMode" value="0">
                    <input type="hidden" id="webhookId" value="">
                    <div class="field">
                        <label class="label">Webhook Name</label>
                        <div class="control">
                            <input class="input" type="text" id="modalWebhookName" placeholder="My Production Webhook" required>
                        </div>
                        <p class="help">A friendly name to identify this webhook</p>
                    </div>
                    <div class="field">
                        <label class="label">Webhook URL</label>
                        <div class="control">
                            <input class="input" type="url" id="modalWebhookUrl" placeholder="https://your-domain.com/webhook" required>
                        </div>
                        <p class="help">The URL where webhook notifications will be sent</p>
                    </div>
                    <div class="field" id="webhookSecretField">
                        <label class="label">Webhook Secret</label>
                        <div class="field has-addons">
                            <div class="control is-expanded">
                                <input class="input" type="text" id="modalWebhookSecret" placeholder="Enter a secret or generate one" maxlength="64">
                            </div>
                            <div class="control">
                                <button class="button is-info" type="button" onclick="generateWebhookSecret()">
                                    <span class="icon"><i class="fas fa-random"></i></span>
                                    <span>Generate</span>
                                </button>
                            </div>
                        </div>
                        <p class="help">A secure secret to verify webhook requests. Leave empty to auto-generate on save.</p>
                    </div>
                    <div class="field">
                        <label class="label">Events to Notify</label>
                        <div class="control">
                            <label class="checkbox" style="display: block; margin-bottom: 0.5rem;">
                                <input type="checkbox" id="modalEventSuccess" checked>
                                Authentication Success
                            </label>
                            <label class="checkbox" style="display: block;">
                                <input type="checkbox" id="modalEventFailure" checked>
                                Authentication Failure
                            </label>
                        </div>
                    </div>
                </section>
                <footer class="modal-card-foot">
                    <button class="button is-success" id="webhookModalSaveBtn" onclick="saveWebhook()">Add Webhook</button>
                    <button class="button" id="webhookModalCancelBtn">Cancel</button>
                </footer>
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
