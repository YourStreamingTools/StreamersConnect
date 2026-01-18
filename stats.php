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
        <div class="footer">
            <p>&copy; <?php echo date('Y'); ?> StreamersConnect - Part of the StreamingTools Ecosystem</p>
        </div>
    </div>
</body>

</html>