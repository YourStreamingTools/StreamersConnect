<?php
session_start();
require_once __DIR__ . '/config/streamersconnect.php';
header('Content-Type: application/json');

// Require login + whitelist
if (!isset($_SESSION['user_id']) || !isWhitelistedUser($_SESSION['user_id'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Forbidden']);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'GET') {
    // List keys (mask key_value)
    $conn = getStreamersConnectDB();
    if (!$conn) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'DB error']);
        exit;
    }
    $res = $conn->query("SELECT kid, is_active, created_at, expires_at FROM auth_signing_keys ORDER BY created_at DESC");
    $keys = [];
    while ($row = $res->fetch_assoc()) {
        $keys[] = $row;
    }
    echo json_encode(['success' => true, 'keys' => $keys]);
    exit;
}

$body = json_decode(file_get_contents('php://input'), true) ?: [];
$action = $body['action'] ?? null;
if ($method === 'POST') {
    if ($action === 'create') {
        // Create a new key. Either provide 'key' or ask to generate one.
        $provided = $body['key'] ?? null;
        $generate = !empty($body['generate']);
        $activate = !empty($body['activate']);
        $expiresAt = $body['expires_at'] ?? null; // optional
        if (!$provided && !$generate) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Provide key or set generate']);
            exit;
        }
        if ($generate) {
            $provided = base64_encode(random_bytes(32));
        }
        $kid = create_signing_key($provided, $activate, $expiresAt);
        if (!$kid) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Failed to create key']);
            exit;
        }
        echo json_encode(['success' => true, 'kid' => $kid, 'key' => $provided]);
        exit;
    } elseif ($action === 'activate') {
        $kid = $body['kid'] ?? null;
        if (!$kid) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'kid is required']);
            exit;
        }
        $ok = activate_signing_key($kid);
        if (!$ok) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Failed to activate key']);
            exit;
        }
        echo json_encode(['success' => true]);
        exit;
    } else {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
        exit;
    }
}

http_response_code(405);
echo json_encode(['success' => false, 'error' => 'Method not allowed']);
exit;
