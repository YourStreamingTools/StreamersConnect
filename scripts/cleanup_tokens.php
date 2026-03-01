<?php
require_once '/var/www/config/streamersconnect.php';
// This script is intended to be run from CLI via cron. If accessed via web, return 403.
if (php_sapi_name() !== 'cli') {
    echo "This script is CLI-only.\n";
    http_response_code(403);
    exit(1);
}

$conn = getStreamersConnectDB();
if (!$conn) {
    echo "DB connection failed\n";
    exit(1);
}

// Delete expired tokens
$res = $conn->query("DELETE FROM auth_tokens WHERE expires_at < NOW()");
$expiredDeleted = $conn->affected_rows;

// Delete consumed tokens older than 1 hour (to allow short window for troubleshooting)
$res2 = $conn->query("DELETE FROM auth_tokens WHERE consumed = 1 AND expires_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)");
$consumedDeleted = $conn->affected_rows;

printf("Cleanup summary: expired_deleted=%d, consumed_deleted=%d\n", $expiredDeleted, $consumedDeleted);
exit(0);
