<?php
session_start();
require_once __DIR__ . '/config/streamersconnect.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}
// Require API key
$apiClient = require_api_key_or_die();
$body = json_decode(file_get_contents('php://input'), true);
if (!$body || empty($body['auth_data_sig'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'auth_data_sig is required']);
    exit;
}
$sig = $body['auth_data_sig'];
$verified = verify_signed_auth_data($sig);
if ($verified === false) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid signature or payload']);
    exit;
}
// Optional origin restriction check
if (!empty($apiClient['allowed_origins']) && !empty($body['origin_domain'])) {
    $allowed = array_map('trim', explode(',', $apiClient['allowed_origins']));
    if (!in_array($body['origin_domain'], $allowed)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Origin not allowed for this API client']);
        exit;
    }
}
// Optionally check origin domain param if provided
if (!empty($body['origin_domain']) && isset($verified['user'])) {
    // Nothing to validate by default; callers can pass origin_domain to compare
}

echo json_encode(['success' => true, 'payload' => $verified]);
exit;
