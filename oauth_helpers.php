<?php
/**
 * OAuth application helpers for StreamersConnect.
 *
 * Lives in the app tree (not /var/www/config) so grouping works after a
 * code deploy even if the production config file has not been recopied yet.
 * Requires streamersconnect.php to be loaded first.
 */

function scHasColumn($conn, $table, $column) {
    static $cache = [];
    if (!$conn) {
        return false;
    }
    $key = $table . '.' . $column;
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    $tableEsc = $conn->real_escape_string($table);
    $columnEsc = $conn->real_escape_string($column);
    $result = $conn->query("SHOW COLUMNS FROM `{$tableEsc}` LIKE '{$columnEsc}'");
    $cache[$key] = $result && $result->num_rows > 0;
    return $cache[$key];
}

function scFindAllowedDomainRow($domain) {
    if (function_exists('findAllowedDomainRow')) {
        return findAllowedDomainRow($domain);
    }
    $conn = getStreamersConnectDB();
    if (!$conn || $domain === '') {
        return null;
    }
    $stmt = $conn->prepare("SELECT * FROM user_allowed_domains WHERE domain = ? LIMIT 1");
    $stmt->bind_param('s', $domain);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

function scOAuthAppColumns($conn) {
    return 'id, user_login, service, app_name, client_id, client_secret, is_default';
}

function scLoadOAuthAppById($appId, $service = null) {
    $conn = getStreamersConnectDB();
    if (!$conn || !$appId) {
        return null;
    }
    $cols = scOAuthAppColumns($conn);
    if ($service) {
        $stmt = $conn->prepare("SELECT {$cols} FROM oauth_applications WHERE id = ? AND service = ? LIMIT 1");
        $stmt->bind_param('is', $appId, $service);
    } else {
        $stmt = $conn->prepare("SELECT {$cols} FROM oauth_applications WHERE id = ? LIMIT 1");
        $stmt->bind_param('i', $appId);
    }
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

function findOAuthAppByClientId($clientId) {
    $conn = getStreamersConnectDB();
    if (!$conn || !$clientId) {
        return null;
    }
    $stmt = $conn->prepare("SELECT " . scOAuthAppColumns($conn) . " FROM oauth_applications WHERE client_id = ? LIMIT 1");
    $stmt->bind_param('s', $clientId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

/**
 * Resolve the OAuth application that will actually be used for this
 * service + origin domain (assigned app, else the domain owner's default).
 */
function resolveOAuthAppForDomain($service, $domain) {
    $conn = getStreamersConnectDB();
    if (!$conn || !$service || !$domain) {
        return null;
    }
    $row = scFindAllowedDomainRow($domain);
    if (!$row) {
        return null;
    }
    if (!empty($row['oauth_app_id'])) {
        $assigned = scLoadOAuthAppById((int)$row['oauth_app_id'], $service);
        if ($assigned) {
            return $assigned;
        }
    }
    $twitchId = $row['twitch_id'] ?? '';
    if ($twitchId === '') {
        return null;
    }
    $stmt = $conn->prepare("
        SELECT oa.id, oa.user_login, oa.service, oa.app_name, oa.client_id, oa.client_secret, oa.is_default
        FROM dashboard_whitelist dw
        INNER JOIN oauth_applications oa ON dw.user_login = oa.user_login
        WHERE dw.twitch_id = ? AND oa.service = ? AND oa.is_default = 1
        LIMIT 1
    ");
    $stmt->bind_param('ss', $twitchId, $service);
    $stmt->execute();
    $app = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $app ?: null;
}

function stampAuthLogOAuthAppId($appId) {
    $conn = getStreamersConnectDB();
    if (!$conn || !$appId) {
        return false;
    }
    if (!scHasColumn($conn, 'auth_logs', 'oauth_app_id')) {
        return false;
    }
    $logId = (int)$conn->insert_id;
    if ($logId <= 0) {
        return false;
    }
    $appId = (int)$appId;
    $stmt = $conn->prepare("UPDATE auth_logs SET oauth_app_id = ? WHERE id = ?");
    if (!$stmt) {
        return false;
    }
    $stmt->bind_param('ii', $appId, $logId);
    $ok = $stmt->execute();
    $stmt->close();
    return $ok;
}

function stampAuthLogOAuthApp($service, $originDomain) {
    $appId = isset($_SESSION['oauth_app_id']) ? (int)$_SESSION['oauth_app_id'] : 0;
    if ($appId > 0) {
        return stampAuthLogOAuthAppId($appId);
    }
    $app = resolveOAuthAppForDomain($service, $originDomain);
    if (!$app) {
        return false;
    }
    return stampAuthLogOAuthAppId((int)$app['id']);
}

function scLogAuthAttempt($service, $originDomain, $userData, $requestedScopes, $success, $errorMessage = null) {
    $result = logAuthAttempt($service, $originDomain, $userData, $requestedScopes, $success, $errorMessage);
    stampAuthLogOAuthApp($service, $originDomain);
    return $result;
}

function scPartnerAuthAppJoins($conn) {
    $loggedJoin = scHasColumn($conn, 'auth_logs', 'oauth_app_id')
        ? "LEFT JOIN oauth_applications oa_logged ON al.oauth_app_id = oa_logged.id"
        : "LEFT JOIN oauth_applications oa_logged ON 1 = 0";
    return $loggedJoin . "
        LEFT JOIN oauth_applications oa_assigned
            ON uad.oauth_app_id = oa_assigned.id AND oa_assigned.service = al.service
        LEFT JOIN oauth_applications oa_default
            ON oa_default.user_login = ? AND oa_default.service = al.service AND oa_default.is_default = 1";
}

function scResolvedAppIdExpr() {
    return "COALESCE(oa_logged.id, oa_assigned.id, oa_default.id)";
}

function scResolvedAppNameExpr() {
    return "COALESCE(oa_logged.app_name, oa_assigned.app_name, oa_default.app_name, 'Unassigned')";
}

function scResolvedAppServiceExpr() {
    return "COALESCE(oa_logged.service, oa_assigned.service, oa_default.service, al.service)";
}

function scFetchPartnerAppStats($conn, $twitchId, $userLogin) {
    $rows = [];
    if (!$conn) {
        return $rows;
    }
    $sql = "
        SELECT
            " . scResolvedAppIdExpr() . " AS app_id,
            " . scResolvedAppNameExpr() . " AS app_name,
            " . scResolvedAppServiceExpr() . " AS app_service,
            MAX(COALESCE(oa_logged.is_default, oa_assigned.is_default, oa_default.is_default, 0)) AS app_is_default,
            COUNT(*) AS auth_count,
            SUM(CASE WHEN al.success = 1 THEN 1 ELSE 0 END) AS successful,
            COUNT(DISTINCT CASE WHEN al.success = 1 AND al.user_id IS NOT NULL THEN al.user_id END) AS unique_users,
            MAX(al.created_at) AS last_auth
        FROM auth_logs al
        INNER JOIN user_allowed_domains uad ON al.origin_domain = uad.domain
        " . scPartnerAuthAppJoins($conn) . "
        WHERE uad.twitch_id = ?
        GROUP BY app_id, app_name, app_service
        ORDER BY auth_count DESC
    ";
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        return $rows;
    }
    $stmt->bind_param('ss', $userLogin, $twitchId);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $rows[] = $row;
    }
    $stmt->close();
    return $rows;
}
