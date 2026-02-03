<?php
session_start();
require_once __DIR__ . '/config/streamersconnect.php';
header('Content-Type: application/json');

// POST only
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Require API key
$apiClient = require_api_key_or_die();

$body = json_decode(file_get_contents('php://input'), true);
if (!$body || empty($body['server_token'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'server_token is required']);
    exit;
}
$serverToken = $body['server_token'];
// If client has allowed_origins configured, optionally enforce origin_domain param
if (!empty($apiClient['allowed_origins']) && !empty($body['origin_domain'])) {
    $allowed = array_map('trim', explode(',', $apiClient['allowed_origins']));
    if (!in_array($body['origin_domain'], $allowed)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Origin not allowed for this API client']);
        exit;
    }
}

// Fetch token
$record = fetch_server_token($serverToken);
if (!$record) {
    http_response_code(404);
    echo json_encode(['success' => false, 'error' => 'Token not found or expired']);
    exit;
}

// Check expiry and consumed
if ($record['consumed'] && intval($record['consumed']) === 1) {
    http_response_code(410);
    echo json_encode(['success' => false, 'error' => 'Token already consumed']);
    exit;
}
if (strtotime($record['expires_at']) < time()) {
    http_response_code(410);
    echo json_encode(['success' => false, 'error' => 'Token expired']);
    exit;
}

// Optionally validate origin_domain if provided by caller
if (!empty($body['origin_domain'])) {
    if ($record['origin_domain'] !== $body['origin_domain']) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Origin mismatch']);
        exit;
    }
}

// Consume token (idempotent for race safety)
if (!consume_server_token($serverToken)) {
    http_response_code(410);
    echo json_encode(['success' => false, 'error' => 'Token invalid or already consumed']);
    exit;
}

$payload = json_decode($record['payload'], true);
echo json_encode(['success' => true, 'payload' => $payload]);
exit;
