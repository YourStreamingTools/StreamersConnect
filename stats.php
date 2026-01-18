<?php
session_start();
require_once '/var/www/config/streamersconnect.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: https://streamersconnect.com/');
    exit;
}

$userLogin = $_SESSION['user_login'];
$twitchId = $_SESSION['user_id'];
$isWhitelisted = isWhitelistedUser($twitchId);

if (!$isWhitelisted) {
    header('Location: /dashboard.php');
    exit;
}

$conn = getStreamersConnectDB();
if (!$conn) {
    die('Database connection error');
}

// Overall stats
$result = $conn->query("
    SELECT 
        COUNT(*) as total_auths,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_auths,
        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_auths,
        SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today,
        SUM(CASE WHEN MONTH(created_at) = MONTH(CURRENT_DATE()) AND YEAR(created_at) = YEAR(CURRENT_DATE()) THEN 1 ELSE 0 END) as this_month,
        MIN(created_at) as first_auth,
        MAX(created_at) as last_auth
    FROM auth_logs
");
$stats = $result->fetch_assoc();
$successRate = $stats['total_auths'] > 0 ? round(($stats['successful_auths'] / $stats['total_auths']) * 100, 2) : 0;

// Stats by domain
$domainStatsResult = $conn->query("
    SELECT 
        origin_domain,
        COUNT(*) as auth_count,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
        MAX(created_at) as last_auth
    FROM auth_logs
    GROUP BY origin_domain
    ORDER BY auth_count DESC
");

// Stats by service
$serviceStatsResult = $conn->query("
    SELECT 
        service,
        COUNT(*) as auth_count,
        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful
    FROM auth_logs
    GROUP BY service
    ORDER BY auth_count DESC
");

// Recent failures
$failuresResult = $conn->query("
    SELECT service, origin_domain, user_login, error_message, created_at
    FROM auth_logs
    WHERE success = 0
    ORDER BY created_at DESC
    LIMIT 10
");

// Unique users
$uniqueUsersResult = $conn->query("
    SELECT COUNT(DISTINCT user_id) as unique_users
    FROM auth_logs
    WHERE success = 1 AND user_id IS NOT NULL
");
$uniqueUsers = $uniqueUsersResult->fetch_assoc();

// Unique users per domain
$stmt = $conn->prepare("
    SELECT 
        al.origin_domain,
        COUNT(DISTINCT al.user_id) as unique_users,
        COUNT(*) as total_auths
    FROM auth_logs al
    INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
    WHERE uad.twitch_id = ? AND al.success = 1 AND al.user_id IS NOT NULL
    GROUP BY al.origin_domain
    ORDER BY unique_users DESC
");
$stmt->bind_param('s', $twitchId);
$stmt->execute();
$uniqueUsersPerDomain = $stmt->get_result();
$stmt->close();

// Recent successful authentications - pagination setup
$recentAuthsPerPage = 10;
$recentAuthsPage = isset($_GET['recent_page']) ? max(1, intval($_GET['recent_page'])) : 1;
$recentAuthsOffset = ($recentAuthsPage - 1) * $recentAuthsPerPage;

// Get total count for pagination
$stmt = $conn->prepare("
    SELECT COUNT(*) as total
    FROM auth_logs al
    INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
    WHERE uad.twitch_id = ? AND al.success = 1
");
$stmt->bind_param('s', $twitchId);
$stmt->execute();
$recentAuthsTotalResult = $stmt->get_result();
$recentAuthsTotal = $recentAuthsTotalResult->fetch_assoc()['total'];
$recentAuthsTotalPages = ceil($recentAuthsTotal / $recentAuthsPerPage);
$stmt->close();

// Get paginated results
$stmt = $conn->prepare("
    SELECT 
        al.service,
        al.origin_domain,
        al.user_id,
        al.user_login,
        al.user_display_name,
        al.created_at
    FROM auth_logs al
    INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
    WHERE uad.twitch_id = ? AND al.success = 1
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
");
$stmt->bind_param('sii', $twitchId, $recentAuthsPerPage, $recentAuthsOffset);
$stmt->execute();
$recentSuccessfulAuths = $stmt->get_result();
$stmt->close();

// Top users by authentication count
$stmt = $conn->prepare("
    SELECT 
        al.user_id,
        al.user_login,
        al.user_display_name,
        al.service,
        COUNT(*) as auth_count,
        MAX(al.created_at) as last_auth,
        MIN(al.created_at) as first_auth
    FROM auth_logs al
    INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
    WHERE uad.twitch_id = ? AND al.success = 1 AND al.user_id IS NOT NULL
    GROUP BY al.user_id, al.user_login, al.user_display_name, al.service
    ORDER BY auth_count DESC
    LIMIT 15
");
$stmt->bind_param('s', $twitchId);
$stmt->execute();
$topUsers = $stmt->get_result();
$stmt->close();

// Daily authentication timeline (last 30 days)
$stmt = $conn->prepare("
    SELECT 
        DATE(al.created_at) as auth_date,
        COUNT(*) as total_auths,
        SUM(CASE WHEN al.success = 1 THEN 1 ELSE 0 END) as successful_auths,
        COUNT(DISTINCT al.user_id) as unique_users
    FROM auth_logs al
    INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
    WHERE uad.twitch_id = ? AND al.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
    GROUP BY DATE(al.created_at)
    ORDER BY auth_date DESC
");
$stmt->bind_param('s', $twitchId);
$stmt->execute();
$dailyTimeline = $stmt->get_result();
$stmt->close();

// All authenticated users with details
$stmt = $conn->prepare("
    SELECT 
        al.user_id,
        al.user_login,
        al.user_display_name,
        al.service,
        COUNT(*) as total_auths,
        MAX(al.created_at) as last_login,
        MIN(al.created_at) as first_login,
        GROUP_CONCAT(DISTINCT al.origin_domain ORDER BY al.origin_domain SEPARATOR ', ') as domains_used
    FROM auth_logs al
    INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
    WHERE uad.twitch_id = ? AND al.success = 1 AND al.user_id IS NOT NULL
    GROUP BY al.user_id, al.user_login, al.user_display_name, al.service
    ORDER BY last_login DESC
");
$stmt->bind_param('s', $twitchId);
$stmt->execute();
$allAuthenticatedUsers = $stmt->get_result();
$stmt->close();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Statistics - StreamersConnect</title>
    <link rel="icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="apple-touch-icon" href="https://cdn.yourstreamingtools.com/img/logo.ico">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.css">
    <link rel="stylesheet" href="custom.css?v=<?php echo filemtime(__DIR__ . '/custom.css'); ?>">
</head>

<body>
    <div class="container container-wide">
        <div class="logo"><i class="fas fa-chart-line"></i></div>
        <h1>StreamersConnect Statistics</h1>
        <p class="subtitle">Detailed Authentication Analytics</p>
        <div class="center-row">
            <a href="/dashboard.php" class="btn btn-small bg-primary zero-margin"><i class="fas fa-arrow-left"></i>
                Dashboard</a>
            <a href="?logout=1" class="btn btn-logout zero-margin">Logout</a>
        </div>
        <!-- Overall Statistics -->
        <div class="info-box">
            <h3><i class="fas fa-chart-bar"></i> Overall Statistics</h3>
            <div class="metrics-grid">
                <div class="metric-card border-primary">
                    <div class="metric-label">Total Authentications</div>
                    <div class="metric-value value-dark"><?php echo number_format($stats['total_auths']); ?></div>
                </div>
                <div class="metric-card border-success">
                    <div class="metric-label">Successful</div>
                    <div class="metric-value value-green"><?php echo number_format($stats['successful_auths']); ?></div>
                </div>
                <div class="metric-card border-danger">
                    <div class="metric-label">Failed</div>
                    <div class="metric-value value-red"><?php echo number_format($stats['failed_auths']); ?></div>
                </div>
                <div class="metric-card border-warning">
                    <div class="metric-label">Success Rate</div>
                    <div class="metric-value value-warning"><?php echo $successRate; ?>%</div>
                </div>
                <div class="metric-card border-indigo">
                    <div class="metric-label">Today</div>
                    <div class="metric-value value-indigo"><?php echo number_format($stats['today']); ?></div>
                </div>
                <div class="metric-card border-pink">
                    <div class="metric-label">This Month</div>
                    <div class="metric-value value-pink"><?php echo number_format($stats['this_month']); ?></div>
                </div>
            </div>
            <?php if ($stats['first_auth']): ?>
                <div class="stats-summary">
                    <strong>First Auth:</strong> <?php echo date('M j, Y g:i A', strtotime($stats['first_auth'])); ?> |
                    <strong>Last Auth:</strong> <?php echo date('M j, Y g:i A', strtotime($stats['last_auth'])); ?> |
                    <strong>Unique Users:</strong> <?php echo number_format($uniqueUsers['unique_users']); ?>
                </div>
            <?php endif; ?>
        </div>
        <!-- By Domain -->
        <div class="info-box">
            <h3><i class="fas fa-globe"></i> Authentication by Domain</h3>
            <div class="table-responsive">
                <table class="table-light">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th class="center">Total</th>
                            <th class="center">Successful</th>
                            <th class="center">Success Rate</th>
                            <th>Last Auth</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $domainStatsResult->fetch_assoc()):
                            $rate = $row['auth_count'] > 0 ? round(($row['successful'] / $row['auth_count']) * 100, 1) : 0;
                            if ($rate >= 95) {
                                $rateClass = 'rate-high';
                            } elseif ($rate >= 80) {
                                $rateClass = 'rate-medium';
                            } else {
                                $rateClass = 'rate-low';
                            }
                            ?>
                            <tr class="table-row">
                                <td><strong><?php echo htmlspecialchars($row['origin_domain']); ?></strong></td>
                                <td class="center"><?php echo number_format($row['auth_count']); ?></td>
                                <td class="center value-green"><?php echo number_format($row['successful']); ?></td>
                                <td class="center"><span class="<?php echo $rateClass; ?>"><?php echo $rate; ?>%</span></td>
                                <td><?php echo date('M j, Y g:i A', strtotime($row['last_auth'])); ?></td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- By Service -->
        <div class="info-box">
            <h3><i class="fas fa-server"></i> Authentication by Service</h3>
            <div class="table-responsive">
                <table class="table-light">
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th class="center">Total</th>
                            <th class="center">Successful</th>
                            <th class="center">Success Rate</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $serviceStatsResult->fetch_assoc()):
                            $rate = $row['auth_count'] > 0 ? round(($row['successful'] / $row['auth_count']) * 100, 1) : 0;
                            $icon = $row['service'] === 'twitch' ? '<i class="fab fa-twitch service-twitch"></i>' : '<i class="fab fa-discord service-discord"></i>';
                            ?>
                            <tr class="table-row">
                                <td><?php echo $icon; ?> <strong><?php echo ucfirst($row['service']); ?></strong></td>
                                <td class="center"><?php echo number_format($row['auth_count']); ?></td>
                                <td class="center value-green"><?php echo number_format($row['successful']); ?></td>
                                <td class="center fw-600"><?php echo $rate; ?>%</td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Recent Failures -->
        <?php if ($failuresResult->num_rows > 0): ?>
            <div class="info-box">
                <h3><i class="fas fa-exclamation-triangle"></i> Recent Failed Authentications</h3>
                <div class="table-responsive">
                    <table class="table-error table-sm">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Service</th>
                                <th>Domain</th>
                                <th>User</th>
                                <th>Error</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($row = $failuresResult->fetch_assoc()): ?>
                                <tr class="table-row">
                                    <td><?php echo date('M j, g:i A', strtotime($row['created_at'])); ?></td>
                                    <td><?php echo ucfirst($row['service']); ?></td>
                                    <td><?php echo htmlspecialchars($row['origin_domain']); ?></td>
                                    <td><?php echo htmlspecialchars($row['user_login'] ?? 'Unknown'); ?></td>
                                    <td class="text-danger"><?php echo htmlspecialchars($row['error_message'] ?? 'Unknown'); ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
        <!-- Unique Users Per Domain -->
        <?php if ($uniqueUsersPerDomain->num_rows > 0): ?>
            <div class="info-box">
                <h3><i class="fas fa-users"></i> Unique Users by Domain</h3>
                <p class="info-text-white">See how many unique users have authenticated to each of your domains.</p>
                <div class="table-responsive">
                    <table class="table-light">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th class="center">Unique Users</th>
                                <th class="center">Total Authentications</th>
                                <th class="center">Avg. Auths per User</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $uniqueUsersPerDomain->data_seek(0);
                            while ($row = $uniqueUsersPerDomain->fetch_assoc()):
                                $avgAuthsPerUser = $row['unique_users'] > 0 ? round($row['total_auths'] / $row['unique_users'], 1) : 0;
                                ?>
                                <tr class="table-row">
                                    <td><strong>
                                            <?php echo htmlspecialchars($row['origin_domain']); ?>
                                        </strong></td>
                                    <td class="center value-indigo fw-600">
                                        <?php echo number_format($row['unique_users']); ?>
                                    </td>
                                    <td class="center">
                                        <?php echo number_format($row['total_auths']); ?>
                                    </td>
                                    <td class="center value-pink fw-600">
                                        <?php echo $avgAuthsPerUser; ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
        <!-- Recent Successful Authentications -->
        <?php if ($recentSuccessfulAuths->num_rows > 0): ?>
            <div class="info-box">
                <h3><i class="fas fa-check-circle"></i> Recent Successful Authentications</h3>
                <p class="info-text-white">Latest successful user logins across all your domains.</p>
                <div class="table-responsive">
                    <table class="table-light table-sm">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Service</th>
                                <th>User</th>
                                <th>Display Name</th>
                                <th>Domain</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $recentSuccessfulAuths->data_seek(0);
                            while ($row = $recentSuccessfulAuths->fetch_assoc()):
                                $icon = $row['service'] === 'twitch' ? '<i class="fab fa-twitch service-twitch"></i>' : '<i class="fab fa-discord service-discord"></i>';
                                ?>
                                <tr class="table-row">
                                    <td>
                                        <?php echo date('M j, g:i A', strtotime($row['created_at'])); ?>
                                    </td>
                                    <td>
                                        <?php echo $icon; ?>
                                        <?php echo ucfirst($row['service']); ?>
                                    </td>
                                    <td><code class="is-size-7"><?php echo htmlspecialchars($row['user_login']); ?></code></td>
                                    <td><strong>
                                            <?php echo htmlspecialchars($row['user_display_name'] ?? $row['user_login']); ?>
                                        </strong></td>
                                    <td>
                                        <?php echo htmlspecialchars($row['origin_domain']); ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
                <?php if ($recentAuthsTotalPages > 1): ?>
                    <div class="pagination-container" style="margin-top: 1rem; text-align: center;">
                        <p class="info-text-white" style="margin-bottom: 0.5rem;">
                            Showing page
                            <?php echo $recentAuthsPage; ?> of
                            <?php echo $recentAuthsTotalPages; ?>
                            (
                            <?php echo number_format($recentAuthsTotal); ?> total authentications)
                        </p>
                        <div class="pagination-buttons">
                            <?php if ($recentAuthsPage > 1): ?>
                                <a href="?recent_page=<?php echo $recentAuthsPage - 1; ?>" class="btn btn-small bg-primary"
                                    style="margin: 0 5px;">
                                    <i class="fas fa-chevron-left"></i> Previous
                                </a>
                            <?php endif; ?>
                            <?php
                            // Show page numbers
                            $startPage = max(1, $recentAuthsPage - 2);
                            $endPage = min($recentAuthsTotalPages, $recentAuthsPage + 2);
                            if ($startPage > 1): ?>
                                <a href="?recent_page=1" class="btn btn-small bg-primary" style="margin: 0 5px;">1</a>
                                <?php if ($startPage > 2): ?>
                                    <span style="color: #cbd5e0; margin: 0 5px;">...</span>
                                <?php endif; ?>
                            <?php endif; ?>
                            <?php for ($i = $startPage; $i <= $endPage; $i++): ?>
                                <?php if ($i == $recentAuthsPage): ?>
                                    <span class="btn btn-small bg-success" style="margin: 0 5px; cursor: default;">
                                        <?php echo $i; ?>
                                    </span>
                                <?php else: ?>
                                    <a href="?recent_page=<?php echo $i; ?>" class="btn btn-small bg-primary" style="margin: 0 5px;">
                                        <?php echo $i; ?>
                                    </a>
                                <?php endif; ?>
                            <?php endfor; ?>
                            <?php if ($endPage < $recentAuthsTotalPages): ?>
                                <?php if ($endPage < $recentAuthsTotalPages - 1): ?>
                                    <span style="color: #cbd5e0; margin: 0 5px;">...</span>
                                <?php endif; ?>
                                <a href="?recent_page=<?php echo $recentAuthsTotalPages; ?>" class="btn btn-small bg-primary"
                                    style="margin: 0 5px;">
                                    <?php echo $recentAuthsTotalPages; ?>
                                </a>
                            <?php endif; ?>
                            <?php if ($recentAuthsPage < $recentAuthsTotalPages): ?>
                                <a href="?recent_page=<?php echo $recentAuthsPage + 1; ?>" class="btn btn-small bg-primary"
                                    style="margin: 0 5px;">
                                    Next <i class="fas fa-chevron-right"></i>
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        <!-- Most Active Users -->
        <?php if ($topUsers->num_rows > 0): ?>
            <div class="info-box">
                <h3><i class="fas fa-trophy"></i> Most Active Users</h3>
                <p class="info-text-white">Users with the highest number of authentications.</p>
                <div class="table-responsive">
                    <table class="table-light">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>User</th>
                                <th>Display Name</th>
                                <th>Service</th>
                                <th class="center">Total Auths</th>
                                <th>First Login</th>
                                <th>Last Login</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $topUsers->data_seek(0);
                            $rank = 1;
                            while ($row = $topUsers->fetch_assoc()):
                                $icon = $row['service'] === 'twitch' ? '<i class="fab fa-twitch service-twitch"></i>' : '<i class="fab fa-discord service-discord"></i>';
                                $rankIcon = '';
                                if ($rank == 1)
                                    $rankIcon = '<i class="fas fa-crown" style="color: #ffd700;"></i> ';
                                elseif ($rank == 2)
                                    $rankIcon = '<i class="fas fa-medal" style="color: #c0c0c0;"></i> ';
                                elseif ($rank == 3)
                                    $rankIcon = '<i class="fas fa-medal" style="color: #cd7f32;"></i> ';
                                ?>
                                <tr class="table-row">
                                    <td class="center">
                                        <?php echo $rankIcon . $rank; ?>
                                    </td>
                                    <td><code class="is-size-7"><?php echo htmlspecialchars($row['user_login']); ?></code></td>
                                    <td><strong>
                                            <?php echo htmlspecialchars($row['user_display_name'] ?? $row['user_login']); ?>
                                        </strong></td>
                                    <td>
                                        <?php echo $icon; ?>
                                        <?php echo ucfirst($row['service']); ?>
                                    </td>
                                    <td class="center value-green fw-600">
                                        <?php echo number_format($row['auth_count']); ?>
                                    </td>
                                    <td>
                                        <?php echo date('M j, Y', strtotime($row['first_auth'])); ?>
                                    </td>
                                    <td>
                                        <?php echo date('M j, Y g:i A', strtotime($row['last_auth'])); ?>
                                    </td>
                                </tr>
                                <?php
                                $rank++;
                            endwhile;
                            ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
        <!-- Daily Authentication Timeline -->
        <?php if ($dailyTimeline->num_rows > 0): ?>
            <div class="info-box">
                <h3><i class="fas fa-calendar-alt"></i> Daily Authentication Timeline (Last 30 Days)</h3>
                <p class="info-text-white">Daily breakdown of authentication activity.</p>
                <div class="table-responsive">
                    <table class="table-light">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th class="center">Total Auths</th>
                                <th class="center">Successful</th>
                                <th class="center">Failed</th>
                                <th class="center">Unique Users</th>
                                <th class="center">Success Rate</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $dailyTimeline->data_seek(0);
                            while ($row = $dailyTimeline->fetch_assoc()):
                                $failed = $row['total_auths'] - $row['successful_auths'];
                                $successRate = $row['total_auths'] > 0 ? round(($row['successful_auths'] / $row['total_auths']) * 100, 1) : 0;
                                if ($successRate >= 95) {
                                    $rateClass = 'rate-high';
                                } elseif ($successRate >= 80) {
                                    $rateClass = 'rate-medium';
                                } else {
                                    $rateClass = 'rate-low';
                                }
                                ?>
                                <tr class="table-row">
                                    <td><strong>
                                            <?php echo date('D, M j, Y', strtotime($row['auth_date'])); ?>
                                        </strong></td>
                                    <td class="center">
                                        <?php echo number_format($row['total_auths']); ?>
                                    </td>
                                    <td class="center value-green">
                                        <?php echo number_format($row['successful_auths']); ?>
                                    </td>
                                    <td class="center value-red">
                                        <?php echo number_format($failed); ?>
                                    </td>
                                    <td class="center value-indigo fw-600">
                                        <?php echo number_format($row['unique_users']); ?>
                                    </td>
                                    <td class="center"><span class="<?php echo $rateClass; ?>">
                                            <?php echo $successRate; ?>%
                                        </span></td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
        <!-- All Authenticated Users -->
        <?php if ($allAuthenticatedUsers->num_rows > 0): ?>
            <div class="info-box">
                <h3><i class="fas fa-user-friends"></i> All Authenticated Users</h3>
                <p class="info-text-white">Complete list of users who have successfully authenticated to your domains.</p>
                <div class="table-responsive">
                    <table class="table-light">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Display Name</th>
                                <th>Service</th>
                                <th class="center">Total Auths</th>
                                <th>Domains Used</th>
                                <th>First Login</th>
                                <th>Last Login</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $allAuthenticatedUsers->data_seek(0);
                            while ($row = $allAuthenticatedUsers->fetch_assoc()):
                                $icon = $row['service'] === 'twitch' ? '<i class="fab fa-twitch service-twitch"></i>' : '<i class="fab fa-discord service-discord"></i>';
                                ?>
                                <tr class="table-row">
                                    <td><code class="is-size-7"><?php echo htmlspecialchars($row['user_login']); ?></code></td>
                                    <td><strong>
                                            <?php echo htmlspecialchars($row['user_display_name'] ?? $row['user_login']); ?>
                                        </strong></td>
                                    <td>
                                        <?php echo $icon; ?>
                                        <?php echo ucfirst($row['service']); ?>
                                    </td>
                                    <td class="center value-green fw-600">
                                        <?php echo number_format($row['total_auths']); ?>
                                    </td>
                                    <td><small>
                                            <?php echo htmlspecialchars($row['domains_used']); ?>
                                        </small></td>
                                    <td>
                                        <?php echo date('M j, Y', strtotime($row['first_login'])); ?>
                                    </td>
                                    <td>
                                        <?php echo date('M j, Y g:i A', strtotime($row['last_login'])); ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
        <div class="footer">
            <p>&copy; <?php echo date('Y'); ?> StreamersConnect - Part of the StreamingTools Ecosystem</p>
        </div>
    </div>
</body>

</html>