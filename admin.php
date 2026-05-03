<?php
session_start();
require_once '/var/www/config/streamersconnect.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: https://streamersconnect.com/');
    exit;
}

$userLogin   = $_SESSION['user_login'];
$twitchId    = $_SESSION['user_id'];
$isWhitelisted = isWhitelistedUser($twitchId);

if (!$isWhitelisted) {
    http_response_code(403);
    die('Access Denied');
}

define('MIGRATIONS_DIR', __DIR__ . '/sql/');

// Ensure the schema_migrations tracking table exists.
// This must happen before any AJAX handler that reads/writes it.
function ensureMigrationsTable() {
    $conn = getStreamersConnectDB();
    if (!$conn) return false;
    $conn->query("CREATE TABLE IF NOT EXISTS schema_migrations (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        filename    VARCHAR(255) NOT NULL UNIQUE,
        applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        applied_by  VARCHAR(100) NOT NULL,
        checksum    VARCHAR(64)  NOT NULL
    )");
    return $conn;
}

// --- AJAX HANDLERS ---
if (isset($_GET['migrations']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $action = $_POST['action'] ?? '';
    $conn   = ensureMigrationsTable();
    if (!$conn) {
        echo json_encode(['success' => false, 'error' => 'Database connection failed']);
        exit;
    }

    if ($action === 'list') {
        $files = is_dir(MIGRATIONS_DIR) ? glob(MIGRATIONS_DIR . '*.sql') : [];
        sort($files);

        $applied = [];
        $result  = $conn->query("SELECT filename, applied_at, applied_by, checksum FROM schema_migrations");
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $applied[$row['filename']] = $row;
            }
        }

        $migrations = [];
        foreach ($files as $file) {
            $name     = basename($file);
            $checksum = hash_file('sha256', $file);
            $isApplied = isset($applied[$name]);
            $migrations[] = [
                'filename'      => $name,
                'applied'       => $isApplied,
                'applied_at'    => $isApplied ? $applied[$name]['applied_at']  : null,
                'applied_by'    => $isApplied ? $applied[$name]['applied_by']  : null,
                'checksum_match'=> $isApplied ? ($applied[$name]['checksum'] === $checksum) : null,
            ];
        }
        echo json_encode(['success' => true, 'migrations' => $migrations]);
        exit;
    }

    if ($action === 'preview') {
        $filename = basename($_POST['filename'] ?? '');
        if (!$filename || !preg_match('/^[a-zA-Z0-9_\-\.]+\.sql$/', $filename)) {
            echo json_encode(['success' => false, 'error' => 'Invalid filename']);
            exit;
        }
        $path = MIGRATIONS_DIR . $filename;
        if (!file_exists($path)) {
            echo json_encode(['success' => false, 'error' => 'File not found']);
            exit;
        }
        echo json_encode(['success' => true, 'sql' => file_get_contents($path)]);
        exit;
    }

    if ($action === 'apply') {
        $filename = basename($_POST['filename'] ?? '');
        if (!$filename || !preg_match('/^[a-zA-Z0-9_\-\.]+\.sql$/', $filename)) {
            echo json_encode(['success' => false, 'error' => 'Invalid filename']);
            exit;
        }
        $path = MIGRATIONS_DIR . $filename;
        if (!file_exists($path)) {
            echo json_encode(['success' => false, 'error' => 'File not found']);
            exit;
        }

        // Check not already applied
        $stmt = $conn->prepare("SELECT id FROM schema_migrations WHERE filename = ?");
        $stmt->bind_param('s', $filename);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            $stmt->close();
            echo json_encode(['success' => false, 'error' => 'Migration already applied']);
            exit;
        }
        $stmt->close();

        $sql      = file_get_contents($path);
        $checksum = hash('sha256', $sql);

        // Execute the migration (supports multiple statements)
        if ($conn->multi_query($sql) === false) {
            echo json_encode(['success' => false, 'error' => 'SQL error: ' . $conn->error]);
            exit;
        }
        // Drain all result sets before issuing new queries
        do {
            if ($res = $conn->store_result()) {
                $res->free();
            }
        } while ($conn->more_results() && $conn->next_result());

        if ($conn->errno) {
            echo json_encode(['success' => false, 'error' => 'SQL error: ' . $conn->error]);
            exit;
        }

        // Record the applied migration
        $stmt = $conn->prepare("INSERT INTO schema_migrations (filename, applied_by, checksum) VALUES (?, ?, ?)");
        $stmt->bind_param('sss', $filename, $userLogin, $checksum);
        $stmt->execute();
        $stmt->close();

        error_log("Migration applied: {$filename} by {$userLogin}");
        echo json_encode(['success' => true]);
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Unknown action']);
    exit;
}

// Pre-flight: ensure table exists for page load too
ensureMigrationsTable();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Migrations - StreamersConnect</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.0/css/all.min.css">
    <link rel="stylesheet" href="custom.css?v=<?php echo filemtime(__DIR__ . '/custom.css'); ?>">
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css">
</head>
<body>
    <div class="container container-wide">
        <div class="logo"><i class="fas fa-database"></i></div>
        <h1>StreamersConnect</h1>
        <p class="subtitle">Admin &mdash; Database Migrations</p>
        <div class="center-row">
            <a href="/dashboard.php" class="btn btn-small bg-primary zero-margin"><i class="fas fa-arrow-left"></i> Dashboard</a>
            <a href="?logout=1" class="btn btn-logout zero-margin">Logout</a>
        </div>

        <div class="info-box">
            <h3><i class="fas fa-database"></i> SQL Migrations</h3>
            <p class="info-text-white">
                Apply pending database schema changes. Click <strong>Preview</strong> to review the SQL before applying.
                Each migration runs exactly once and is tracked by filename.
            </p>
            <div id="migrationsContainer">
                <div class="notification is-info is-light has-text-centered">
                    <i class="fas fa-spinner fa-spin"></i> Loading migrations&hellip;
                </div>
            </div>
            <div style="margin-top: 1rem;">
                <button class="button is-light is-small" onclick="renderMigrations()">
                    <span class="icon"><i class="fas fa-rotate"></i></span>
                    <span>Refresh</span>
                </button>
            </div>
        </div>

        <!-- SQL Preview Modal -->
        <div id="previewModal" class="modal">
            <div class="modal-background" onclick="closePreviewModal()"></div>
            <div class="modal-card" style="max-width:800px;width:95vw;">
                <header class="modal-card-head">
                    <p class="modal-card-title" id="previewModalTitle">Migration Preview</p>
                    <button class="delete" aria-label="close" onclick="closePreviewModal()"></button>
                </header>
                <section class="modal-card-body">
                    <pre id="previewSql" style="background:#1a1a2e;color:#e2e8f0;padding:1rem;border-radius:6px;overflow-x:auto;max-height:60vh;white-space:pre-wrap;font-size:0.85rem;line-height:1.5;"></pre>
                </section>
                <footer class="modal-card-foot" style="gap: 0.5rem;">
                    <button class="button" onclick="closePreviewModal()">Close</button>
                    <button class="button is-success" id="previewApplyBtn" style="display:none;">
                        <span class="icon"><i class="fas fa-play"></i></span>
                        <span>Apply Migration</span>
                    </button>
                </footer>
            </div>
        </div>

        <div class="footer">
            <p>&copy; <?php echo date('Y'); ?> StreamersConnect &mdash; Part of the StreamingTools Ecosystem</p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
    <script>
        function toast(text, ok) {
            Toastify({
                text,
                duration: 4000,
                gravity: 'top',
                position: 'right',
                backgroundColor: ok ? '#48bb78' : '#ef4444',
                stopOnFocus: true
            }).showToast();
        }

        function renderMigrations() {
            const container = document.getElementById('migrationsContainer');
            container.innerHTML = '<div class="notification is-light has-text-centered"><i class="fas fa-spinner fa-spin"></i> Loading&hellip;</div>';

            fetch('?migrations=1', {
                method: 'POST',
                body: new URLSearchParams({ action: 'list' })
            })
            .then(r => r.json())
            .then(res => {
                if (!res.success) {
                    container.innerHTML = '<div class="notification is-danger">Failed to load migrations.</div>';
                    return;
                }
                if (!res.migrations.length) {
                    container.innerHTML = '<div class="notification is-info is-light has-text-centered"><i class="fas fa-folder-open"></i> No <code>.sql</code> files found in the <code>sql/</code> directory.</div>';
                    return;
                }

                const pending = res.migrations.filter(m => !m.applied).length;
                let html = pending > 0
                    ? `<div class="notification is-warning is-light"><i class="fas fa-triangle-exclamation"></i> <strong>${pending}</strong> pending migration${pending !== 1 ? 's' : ''} to apply.</div>`
                    : `<div class="notification is-success is-light"><i class="fas fa-circle-check"></i> All migrations are up to date.</div>`;

                html += `<div class="table-container">
                    <table class="table is-fullwidth is-striped is-hoverable">
                        <thead>
                            <tr>
                                <th style="width:120px;">Status</th>
                                <th><i class="fas fa-file-code"></i> Migration File</th>
                                <th>Applied At</th>
                                <th>Applied By</th>
                                <th class="has-text-centered" style="width:160px;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>`;

                res.migrations.forEach(m => {
                    let statusBadge;
                    if (m.applied) {
                        statusBadge = `<span class="tag is-success"><i class="fas fa-check"></i>&nbsp;Applied</span>`;
                        if (m.checksum_match === false) {
                            statusBadge += `&nbsp;<span class="tag is-warning" title="File modified after it was applied"><i class="fas fa-triangle-exclamation"></i>&nbsp;Modified</span>`;
                        }
                    } else {
                        statusBadge = `<span class="tag is-warning"><i class="fas fa-clock"></i>&nbsp;Pending</span>`;
                    }

                    const appliedAt  = m.applied_at  ? new Date(m.applied_at).toLocaleString() : '&mdash;';
                    const appliedBy  = m.applied_by  ? m.applied_by : '&mdash;';
                    const safeFile   = m.filename.replace(/'/g, "\\'");

                    const applyBtn = m.applied
                        ? `<button class="button is-small is-light" disabled title="Already applied"><i class="fas fa-check"></i></button>`
                        : `<button class="button is-small is-success" onclick="previewAndApply('${safeFile}')">
                               <span class="icon is-small"><i class="fas fa-play"></i></span>
                               <span>Apply</span>
                           </button>`;

                    html += `<tr>
                        <td>${statusBadge}</td>
                        <td><code>${m.filename}</code></td>
                        <td class="is-size-7 has-text-grey-light">${appliedAt}</td>
                        <td class="is-size-7 has-text-grey-light">${appliedBy}</td>
                        <td class="has-text-centered">
                            <div class="buttons is-centered">
                                <button class="button is-small is-info" onclick="previewOnly('${safeFile}')">
                                    <span class="icon is-small"><i class="fas fa-eye"></i></span>
                                    <span>Preview</span>
                                </button>
                                ${applyBtn}
                            </div>
                        </td>
                    </tr>`;
                });

                html += `</tbody></table></div>`;
                container.innerHTML = html;
            })
            .catch(() => {
                container.innerHTML = '<div class="notification is-danger">Request failed.</div>';
            });
        }

        function previewOnly(filename) {
            document.getElementById('previewApplyBtn').style.display = 'none';
            loadPreview(filename);
        }

        function previewAndApply(filename) {
            const btn = document.getElementById('previewApplyBtn');
            btn.style.display = '';
            btn.onclick = () => applyMigration(filename);
            loadPreview(filename);
        }

        function loadPreview(filename) {
            document.getElementById('previewModalTitle').textContent = filename;
            document.getElementById('previewSql').textContent = 'Loading…';
            document.getElementById('previewModal').classList.add('is-active');

            fetch('?migrations=1', {
                method: 'POST',
                body: new URLSearchParams({ action: 'preview', filename })
            })
            .then(r => r.json())
            .then(res => {
                document.getElementById('previewSql').textContent = res.success ? res.sql : ('Error: ' + res.error);
            });
        }

        function closePreviewModal() {
            document.getElementById('previewModal').classList.remove('is-active');
        }

        function applyMigration(filename) {
            closePreviewModal();
            if (!confirm('Apply migration "' + filename + '"?\n\nThis will execute the SQL against the live database and cannot be undone.')) return;

            toast('Applying ' + filename + '…', true);

            fetch('?migrations=1', {
                method: 'POST',
                body: new URLSearchParams({ action: 'apply', filename })
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    toast('Migration applied successfully!', true);
                    renderMigrations();
                } else {
                    toast('Failed: ' + (res.error || 'Unknown error'), false);
                }
            })
            .catch(() => toast('Request failed', false));
        }

        document.addEventListener('DOMContentLoaded', renderMigrations);
    </script>
</body>
</html>
