<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
// Load configuration from the canonical installed config directory only.
$configPath = '/var/www/config/streamersconnect.php';
if (file_exists($configPath)) {
    require_once $configPath;
    error_log('api_clients.php loaded config: ' . $configPath);
} else {
    header('Content-Type: application/json');
    http_response_code(500);
    error_log('api_clients.php could not find config at: ' . $configPath);
    echo json_encode(['success' => false, 'error' => 'Server configuration missing']);
    exit;
}
header('Content-Type: application/json');

// Convert PHP errors to exceptions and return JSON on failure
set_error_handler(function($severity, $message, $file, $line) { throw new ErrorException($message, 0, $severity, $file, $line); });
try {
    // Allow authenticated users; admin users (whitelist) may manage all clients
    if (!isset($_SESSION['user_id'])) {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Forbidden']);
        exit;
    }
    $isAdmin = isWhitelistedUser($_SESSION['user_id']);
    $method = $_SERVER['REQUEST_METHOD'];
    if ($method === 'GET') {
        // Log request context for diagnostics
        error_log('api_clients.php GET invoked by user_id=' . ($_SESSION['user_id'] ?? 'none') . ' isAdmin=' . ($isAdmin ? '1':'0'));
        try {
            // If admin, list all clients; otherwise return the caller's client (if any)
            if ($isAdmin) {
                $clients = list_api_clients();
                echo json_encode(['success' => true, 'clients' => $clients]);
                exit;
            } else {
                $client = get_api_client_by_owner($_SESSION['user_id']);
                echo json_encode(['success' => true, 'client' => $client]);
                exit;
            }
        } catch (Throwable $e) {
            error_log('api_clients.php GET error: ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Failed to load API client info']);
            exit;
        }
    }

$body = json_decode(file_get_contents('php://input'), true) ?: [];
$action = $body['action'] ?? null;
if ($method === 'POST') {
    if ($action === 'create') {
        $name = trim($body['name'] ?? 'API Client');
        $allowedOrigins = $body['allowed_origins'] ?? null;
        // Determine owner: admins may provide owner_twitch_id; otherwise default to the creating user's Twitch ID
        if ($isAdmin) {
            $owner = $body['owner_twitch_id'] ?? ($_SESSION['user_id'] ?? null);
        } else {
            $owner = $_SESSION['user_id'] ?? null;
        }
        // If not admin, ensure single-client restriction
        if (!$isAdmin) {
            $existing = get_api_client_by_owner($owner);
            if ($existing) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'You already have an API client. Please rotate or deactivate it.']);
                exit;
            }
        }
        if (!$name) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Name is required']);
            exit;
        }
        // Create client
        $result = create_api_client($name, $owner, $allowedOrigins, true);
        if (!$result) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Failed to create client']);
            exit;
        }
        // Fetch the created client row to include owner info
        $clientRow = get_api_client_by_client_id($result['client_id']);
        echo json_encode(['success' => true, 'client_id' => $result['client_id'], 'api_key' => $result['api_key'], 'client' => $clientRow]);
        exit;
    } elseif ($action === 'deactivate') {
        $clientId = $body['client_id'] ?? null;
        if (!$clientId) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'client_id required']);
            exit;
        }
        // Ensure ownership unless admin
        $client = get_api_client_by_client_id($clientId);
        if (!$client) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Client not found']);
            exit;
        }
        if (!$isAdmin && $client['owner_twitch_id'] !== $_SESSION['user_id']) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Not allowed']);
            exit;
        }
        $ok = deactivate_api_client($clientId);
        echo json_encode(['success' => $ok]);
        exit;
    } elseif ($action === 'rotate') {
        $clientId = $body['client_id'] ?? null;
        if (!$clientId) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'client_id required']);
            exit;
        }
        $client = get_api_client_by_client_id($clientId);
        if (!$client) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Client not found']);
            exit;
        }
        if (!$isAdmin && $client['owner_twitch_id'] !== $_SESSION['user_id']) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Not allowed']);
            exit;
        }
        $newKey = rotate_api_client_key($clientId);
        if (!$newKey) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Failed to rotate key']);
            exit;
        }
        echo json_encode(['success' => true, 'api_key' => $newKey]);
        exit;
    } elseif ($action === 'reveal') {
        $clientId = $body['client_id'] ?? null;
        if (!$clientId) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'client_id required']);
            exit;
        }
        $client = get_api_client_by_client_id($clientId);
        if (!$client) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Client not found']);
            exit;
        }
        if (!$isAdmin && $client['owner_twitch_id'] !== $_SESSION['user_id']) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Not allowed']);
            exit;
        }
        // Log reveal event for auditing
        error_log('api_clients.php reveal by user ' . ($_SESSION['user_id'] ?? 'unknown') . ' for client ' . $clientId);
        // Optionally record usage
        @record_api_client_usage($client['client_id']);
        echo json_encode(['success' => true, 'api_key' => $client['api_key']]);
        exit;
    }
}

http_response_code(405);
echo json_encode(['success' => false, 'error' => 'Method not allowed']);
exit;
}
catch (Throwable $e) {
    error_log('api_clients.php error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Internal server error']);
    exit;
}
