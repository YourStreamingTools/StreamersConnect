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
                $stmt = $conn->prepare("INSERT INTO oauth_applications (user_id, user_login, service, app_name, client_id, client_secret, is_default) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param('ssssssi', $twitchId, $userLogin, $service, $app_name, $client_id, $client_secret, $is_default);
                $ok = $stmt->execute();
                $stmt->close();
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
                $stmt = $conn->prepare("UPDATE oauth_applications SET service=?, app_name=?, client_id=?, client_secret=?, is_default=? WHERE id=? AND user_login=?");
                $stmt->bind_param('ssssiis', $service, $app_name, $client_id, $client_secret, $is_default, $id, $userLogin);
                $ok = $stmt->execute();
                $stmt->close();
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
                if ($domain) {
                    $stmt = $conn->prepare("INSERT INTO user_allowed_domains (twitch_id, domain, notes) VALUES (?, ?, ?)");
                    $stmt->bind_param('sss', $twitchId, $domain, $notes);
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
                if ($id && $domain) {
                    $stmt = $conn->prepare("UPDATE user_allowed_domains SET domain=?, notes=? WHERE id=? AND twitch_id=?");
                    $stmt->bind_param('ssis', $domain, $notes, $id, $twitchId);
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
                $stmt = $conn->prepare("SELECT id, domain, notes, created_at FROM user_allowed_domains WHERE twitch_id=? ORDER BY domain ASC");
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
        // Get recent authentication attempts (last 5)
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
            LIMIT 5
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
            <h3><i class="fas fa-key"></i> OAuth Applications</h3>
            <p class="info-text-white">Manage your OAuth applications and credentials.</p>
            <?php if ($isWhitelisted): ?>
                <!-- Bulma Modal for OAuth App -->
                <div id="oauthAppModal" class="modal">
                    <div class="modal-background"></div>
                    <div class="modal-card">
                        <header class="modal-card-head">
                            <p class="modal-card-title" id="modalTitle">New OAuth Application</p>
                            <button class="delete" aria-label="close" onclick="hideOAuthAppModal()"></button>
                        </header>
                        <section class="modal-card-body" id="modalBody">
                            <!-- Form content will be injected here by JS -->
                        </section>
                        <footer class="modal-card-foot" id="modalFooter">
                            <!-- Action buttons will be injected here by JS -->
                        </footer>
                    </div>
                </div>
                <div id="oauthAppsContainer"></div>
                <button class="button is-primary is-small mt-10" id="createAppBtn"><i class="fas fa-plus"></i> Create New Application</button>
            <?php endif; ?>
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
                        list.innerHTML = '<div class="notification is-info">No OAuth applications yet.</div>';
                        return;
                    }
                    let html = '';
                    res.apps.forEach(function(app) {
                        const defaultBadge = app.is_default ? '<span class="tag is-success ml-2"><i class="fas fa-check-circle"></i> Default</span>' : '';
                        html += `<div class="box" data-id="${app.id}" style="margin-bottom: 1rem;">
                            <h4 class="title is-5">${app.app_name} <span class="tag is-primary">${app.service}</span>${defaultBadge}</h4>
                            <p><strong>Client ID:</strong> ${app.client_id}</p>
                            <p class="help">Redirects and scopes are determined by the <code>&return_url=</code> and <code>&scopes=</code> parameters in authentication requests</p>
                            <div class="buttons" style="margin-top: 1rem;">
                                <button class="button is-small is-info oauthAppEditBtn"><i class="fas fa-edit"></i> Edit</button>
                                <button class="button is-small is-danger oauthAppDeleteBtn"><i class="fas fa-trash"></i> Delete</button>
                            </div>
                        </div>`;
                    });
                    list.innerHTML = html;
                });
            }
            function showOAuthAppModal(edit, app) {
                const modal = document.getElementById('oauthAppModal');
                const modalTitle = document.getElementById('modalTitle');
                const modalBody = document.getElementById('modalBody');
                const modalFooter = document.getElementById('modalFooter');
                // Set modal title
                modalTitle.textContent = edit ? 'Edit OAuth Application' : 'New OAuth Application';
                // Build form (use Bulma classes)
                let formHtml = '';
                formHtml += '<div class="field">';
                formHtml += '<label class="label">Service</label>';
                formHtml += '<div class="control">';
                formHtml += '<div class="select is-fullwidth">';
                formHtml += '<select id="modalService">';
                formHtml += '<option value="twitch"'+((app && app.service==="twitch")?" selected":"")+'>Twitch</option>';
                formHtml += '<option value="discord"'+((app && app.service==="discord")?" selected":"")+'>Discord</option>';
                formHtml += '</select>';
                formHtml += '</div></div></div>';
                formHtml += '<div class="field">';
                formHtml += '<label class="label">App Name</label>';
                formHtml += '<div class="control">';
                formHtml += '<input class="input" type="text" id="modalAppName" value="'+(app?app.app_name:'')+'" maxlength="64">';
                formHtml += '</div></div>';
                formHtml += '<div class="field">';
                formHtml += '<label class="label">Client ID</label>';
                formHtml += '<div class="control">';
                formHtml += '<input class="input" type="text" id="modalClientId" value="'+(app?app.client_id:'')+'" maxlength="128">';
                formHtml += '</div></div>';
                formHtml += '<div class="field">';
                formHtml += '<label class="label">Client Secret</label>';
                formHtml += '<div class="control">';
                formHtml += '<input class="input" type="text" id="modalClientSecret" value="'+(app?app.client_secret:'')+'" maxlength="128">';
                formHtml += '</div></div>';
                formHtml += '<div class="field">';
                formHtml += '<label class="checkbox">';
                formHtml += '<input type="checkbox" id="modalIsDefault" '+((app && app.is_default) ? 'checked' : '')+'>  Use as default credentials';
                formHtml += '</label>';
                formHtml += '<p class="help">If checked, this will be used when no custom OAuth credentials are provided via headers. Scopes are specified per authentication request via the <code>&scopes=</code> URL parameter.</p>';
                formHtml += '</div>';
                modalBody.innerHTML = formHtml;
                // Footer buttons
                let footerHtml = '';
                footerHtml += '<button class="button is-success" id="modalSaveBtn">'+(edit?'Save Changes':'Create Application')+'</button>';
                footerHtml += '<button class="button" id="modalCancelBtn">Cancel</button>';
                modalFooter.innerHTML = footerHtml;
                // Show modal
                modal.classList.add('is-active');
                // Button handlers
                document.getElementById('modalCancelBtn').onclick = hideOAuthAppModal;
                document.getElementById('modalSaveBtn').onclick = function() {
                    // Gather form data
                    var service = document.getElementById('modalService').value;
                    var appName = document.getElementById('modalAppName').value.trim();
                    var clientId = document.getElementById('modalClientId').value.trim();
                    var clientSecret = document.getElementById('modalClientSecret').value.trim();
                    var isDefault = document.getElementById('modalIsDefault').checked;
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
                    data.append('action', edit ? 'edit' : 'create');
                    if (edit && app) data.append('id', app.id);
                    data.append('service', service);
                    data.append('app_name', appName);
                    data.append('client_id', clientId);
                    data.append('client_secret', clientSecret);
                    if (isDefault) data.append('is_default', '1');
                    fetch('?oauth_app=1', {
                        method: 'POST',
                        body: data
                    })
                    .then(r => r.json())
                    .then(res => {
                        Toastify({
                            text: res.success ? (edit ? "Application updated!" : "Application created!") : "Save failed.",
                            duration: 3000,
                            gravity: "top",
                            position: "right",
                            backgroundColor: res.success ? "#48bb78" : "#ef4444",
                            stopOnFocus: true
                        }).showToast();
                        if (res.success) {
                            hideOAuthAppModal();
                            renderOAuthApps();
                        }
                    });
                };
            }
            function hideOAuthAppModal() {
                const modal = document.getElementById('oauthAppModal');
                modal.classList.remove('is-active');
            }
        document.addEventListener('DOMContentLoaded', function() {
            // OAuth app list
            if (document.getElementById('oauthAppsContainer')) {
                renderOAuthApps();
            }
            // Create app button
            var createBtn = document.getElementById('createAppBtn');
            if (createBtn) {
                createBtn.addEventListener('click', function() {
                    showOAuthAppModal(false, null);
                });
            }
            // Close modal when clicking background
            var modalBg = document.querySelector('#oauthAppModal .modal-background');
            if (modalBg) {
                modalBg.addEventListener('click', hideOAuthAppModal);
            }
            // Edit/Delete buttons (event delegation)
            document.body.addEventListener('click', function(e) {
                if (e.target.classList.contains('oauthAppEditBtn') || e.target.closest('.oauthAppEditBtn')) {
                    var btn = e.target.classList.contains('oauthAppEditBtn') ? e.target : e.target.closest('.oauthAppEditBtn');
                    var card = btn.closest('.box');
                    var id = card.getAttribute('data-id');
                    fetch('?oauth_app=1', {
                        method: 'POST',
                        body: new URLSearchParams({action: 'list'})
                    })
                    .then(r => r.json())
                    .then(res => {
                        var app = res.apps.find(a => a.id == id);
                        if (app) showOAuthAppModal(true, app);
                    });
                }
                if (e.target.classList.contains('oauthAppDeleteBtn') || e.target.closest('.oauthAppDeleteBtn')) {
                    if (!confirm('Delete this application?')) return;
                    var btn = e.target.classList.contains('oauthAppDeleteBtn') ? e.target : e.target.closest('.oauthAppDeleteBtn');
                    var card = btn.closest('.box');
                    var id = card.getAttribute('data-id');
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
                    html += `
                        <tr data-id="${domain.id}">
                            <td><strong>${domain.domain}</strong></td>
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
            const modalBody = document.getElementById('domainModalBody');
            const modalFooter = document.getElementById('domainModalFooter');
            modalTitle.textContent = edit ? 'Edit Domain' : 'Add New Domain';
            let formHtml = '';
            formHtml += '<div class="field">';
            formHtml += '<label class="label">Domain</label>';
            formHtml += '<div class="control">';
            formHtml += '<input class="input" type="text" id="modalDomain" value="'+(domain?domain.domain:'')+'" placeholder="example.com" maxlength="255">';
            formHtml += '</div></div>';
            formHtml += '<div class="field">';
            formHtml += '<label class="label">Notes (optional)</label>';
            formHtml += '<div class="control">';
            formHtml += '<textarea class="textarea" id="modalDomainNotes" maxlength="500">'+(domain?domain.notes:'')+'</textarea>';
            formHtml += '</div></div>';
            modalBody.innerHTML = formHtml;
            let footerHtml = '';
            footerHtml += '<button class="button is-success" id="domainModalSaveBtn">'+(edit?'Save Changes':'Add Domain')+'</button>';
            footerHtml += '<button class="button" id="domainModalCancelBtn">Cancel</button>';
            modalFooter.innerHTML = footerHtml;
            modal.classList.add('is-active');
            document.getElementById('domainModalCancelBtn').onclick = hideDomainModal;
            document.getElementById('domainModalSaveBtn').onclick = function() {
                var domainValue = document.getElementById('modalDomain').value.trim();
                var notes = document.getElementById('modalDomainNotes').value.trim();
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
                data.append('action', edit ? 'edit' : 'create');
                if (edit && domain) data.append('id', domain.id);
                data.append('domain', domainValue);
                data.append('notes', notes);
                fetch('?domain=1', {
                    method: 'POST',
                    body: data
                })
                .then(r => r.json())
                .then(res => {
                    Toastify({
                        text: res.success ? (edit ? "Domain updated!" : "Domain added!") : "Save failed.",
                        duration: 3000,
                        gravity: "top",
                        position: "right",
                        backgroundColor: res.success ? "#48bb78" : "#ef4444",
                        stopOnFocus: true
                    }).showToast();
                    if (res.success) {
                        hideDomainModal();
                        renderDomains();
                    }
                });
            };
        }
        function hideDomainModal() {
            const modal = document.getElementById('domainModal');
            modal.classList.remove('is-active');
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
            var createDomainBtn = document.getElementById('createDomainBtn');
            if (createDomainBtn) {
                createDomainBtn.addEventListener('click', function() {
                    showDomainModal(false, null);
                });
            }
            var domainModalBg = document.querySelector('#domainModal .modal-background');
            if (domainModalBg) {
                domainModalBg.addEventListener('click', hideDomainModal);
            }
        });
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
                            <button class="delete" aria-label="close" onclick="hideDomainModal()"></button>
                        </header>
                        <section class="modal-card-body" id="domainModalBody">
                            <!-- Form content will be injected here by JS -->
                        </section>
                        <footer class="modal-card-foot" id="domainModalFooter">
                            <!-- Action buttons will be injected here by JS -->
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
