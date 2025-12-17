<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';
$token = $input['token'] ?? '';

require_once '../config/database.php';

// Helper functions
function parseTimeToSeconds($timeStr) {
    if (empty($timeStr) || !is_string($timeStr)) return 0;
    $matches = [];
    $parts = preg_match('/(\d+)h\s*(\d+)m\s*(\d+)s/', $timeStr, $matches);
    if (!$parts || count($matches) < 4) return 0;
    return intval($matches[1]) * 3600 + intval($matches[2]) * 60 + intval($matches[3]);
}

function secondsToTimeString($seconds) {
    if ($seconds < 0) $seconds = 0;
    $hours = floor($seconds / 3600);
    $minutes = floor(($seconds % 3600) / 60);
    $secs = $seconds % 60;
    return sprintf('%dh %dm %ds', $hours, $minutes, $secs);
}

// Verify token
function verifyToken($pdo, $token) {
    $stmt = $pdo->prepare("SELECT id, name, token FROM users WHERE token = ?");
    $stmt->execute([$token]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

$user = verifyToken($pdo, $token);
if (!$user) {
    echo json_encode(['success' => false, 'message' => 'Invalid token']);
    exit;
}

switch ($action) {
    case 'getTimeLeft':
        try {
            // Try to get time_left and last_time_update (if column exists)
            // First, check if last_time_update column exists
            $stmt = $pdo->prepare("SHOW COLUMNS FROM users LIKE 'last_time_update'");
            $stmt->execute();
            $hasTimeUpdateColumn = $stmt->rowCount() > 0;
            
            if ($hasTimeUpdateColumn) {
                // Use last_time_update column
                $stmt = $pdo->prepare("SELECT time_left, last_time_update FROM users WHERE token = ?");
                $stmt->execute([$token]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($result) {
                    $currentSeconds = parseTimeToSeconds($result['time_left']);
                    $lastUpdate = $result['last_time_update'];
                    
                    if ($lastUpdate) {
                        // Calculate elapsed time since last update
                        $stmt = $pdo->prepare("SELECT TIMESTAMPDIFF(SECOND, ?, NOW()) as elapsed");
                        $stmt->execute([$lastUpdate]);
                        $elapsedResult = $stmt->fetch(PDO::FETCH_ASSOC);
                        $elapsedSeconds = $elapsedResult['elapsed'] ?? 0;
                        
                        // Subtract elapsed time
                        $newSeconds = max(0, $currentSeconds - $elapsedSeconds);
                        $newTime = secondsToTimeString($newSeconds);
                        
                        // Update database with new time and timestamp
                        $stmt = $pdo->prepare("UPDATE users SET time_left = ?, last_time_update = NOW() WHERE token = ?");
                        $stmt->execute([$newTime, $token]);
                        
                        echo json_encode(['success' => true, 'timeLeft' => $newTime]);
                    } else {
                        // No last update, just return current time and set timestamp
                        $stmt = $pdo->prepare("UPDATE users SET last_time_update = NOW() WHERE token = ?");
                        $stmt->execute([$token]);
                        echo json_encode(['success' => true, 'timeLeft' => $result['time_left']]);
                    }
                } else {
                    echo json_encode(['success' => false, 'message' => 'User not found']);
                }
            } else {
                // Column doesn't exist, add it and use it
                try {
                    $pdo->exec("ALTER TABLE users ADD COLUMN last_time_update DATETIME NULL");
                } catch (Exception $e) {
                    // Column might already exist or other error, continue
                }
                
                // Now fetch and update
                $stmt = $pdo->prepare("SELECT time_left FROM users WHERE token = ?");
                $stmt->execute([$token]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($result) {
                    // Set initial timestamp
                    $stmt = $pdo->prepare("UPDATE users SET last_time_update = NOW() WHERE token = ?");
                    $stmt->execute([$token]);
                    echo json_encode(['success' => true, 'timeLeft' => $result['time_left']]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'User not found']);
                }
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
        }
        break;
        
    case 'updateTimeLeft':
        $timeLeft = $input['timeLeft'] ?? '';
        try {
            // Update time_left and last_time_update timestamp
            $stmt = $pdo->prepare("UPDATE users SET time_left = ?, last_time_update = NOW() WHERE token = ?");
            $stmt->execute([$timeLeft, $token]);
            echo json_encode(['success' => true, 'message' => 'Time updated successfully']);
        } catch (Exception $e) {
            // If last_time_update column doesn't exist, try without it
            try {
                $stmt = $pdo->prepare("UPDATE users SET time_left = ? WHERE token = ?");
                $stmt->execute([$timeLeft, $token]);
                echo json_encode(['success' => true, 'message' => 'Time updated successfully']);
            } catch (Exception $e2) {
                echo json_encode(['success' => false, 'message' => 'Database error: ' . $e2->getMessage()]);
            }
        }
        break;
        
    case 'updateConnectionStatus':
        $connected = $input['connected'] ?? false;
        try {
            // Update connection status in database
            $stmt = $pdo->prepare("UPDATE users SET connection_status = ?, last_connection_update = NOW() WHERE token = ?");
            $stmt->execute([$connected ? 1 : 0, $token]);
            
            // Log the connection change
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "User " . ($connected ? 'connected' : 'disconnected') . " via tray application", $user['id']]);
            
            echo json_encode(['success' => true, 'message' => 'Connection status updated']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
        }
        break;
        
    case 'getConnectionStatus':
        try {
            $stmt = $pdo->prepare("SELECT connection_status FROM users WHERE token = ?");
            $stmt->execute([$token]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result) {
                $connected = $result['connection_status'] == 1;
                echo json_encode(['success' => true, 'connected' => $connected]);
            } else {
                echo json_encode(['success' => false, 'message' => 'User not found']);
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
        }
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
}
?>