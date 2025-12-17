<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';
$token = $input['token'] ?? '';

if ($action === 'login') {
    if (empty($token)) {
        echo json_encode(['success' => false, 'message' => 'Token is required']);
        exit;
    }

    // Use database now
    require_once '../config/database.php';

    // Look up the user by token
    $stmt = $pdo->prepare("SELECT id, name, token FROM users WHERE token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Log successful login
                $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
                $stmt->execute(['info', "User logged in successfully", $user['id']]);
                
                // Update last login
                $stmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $stmt->execute([$user['id']]);
                
                echo json_encode([
                    'success' => true,
                    'user' => [
                        'id' => $user['id'],
                        'name' => $user['name'],
                        'token' => $user['token']
                    ]
                ]);
            } else {
                // Log failed login attempt
                $stmt = $pdo->prepare("INSERT INTO system_logs (level, message) VALUES (?, ?)");
                $stmt->execute(['warning', "Failed login attempt with token: " . substr($token, 0, 6) . "..."]); 
                
                echo json_encode(['success' => false, 'message' => 'Invalid token.']);
            }
}
else if ($action === 'logout') {
    echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid action']);
}
?>