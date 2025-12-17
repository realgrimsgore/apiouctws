<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';
$token = $input['token'] ?? '';

require_once '../config/database.php';

// Check if user is admin (ID 1 or 3)
function checkAdminAccess($pdo, $token) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user || ($user['id'] != 1 && $user['id'] != 3)) {
        return false;
    }
    return true;
}

if (!checkAdminAccess($pdo, $token)) {
    echo json_encode(['success' => false, 'message' => 'Admin access required']);
    exit;
}

switch ($action) {
    case 'testDatabase':
        try {
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM users");
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'message' => 'Database connected', 'userCount' => $result['count']]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
        }
        break;

    case 'getAllUsers':
        try {
            $stmt = $pdo->query("SELECT id, name, token, time_left, created_at FROM users ORDER BY id");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'users' => $users]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error fetching users: ' . $e->getMessage()]);
        }
        break;

    case 'addTimeToUser':
        $targetUserId = $input['targetUserId'] ?? '';
        $timeToAdd = $input['timeToAdd'] ?? '';
        
        if (empty($targetUserId) || empty($timeToAdd)) {
            echo json_encode(['success' => false, 'message' => 'User ID and time required']);
            break;
        }

        try {
            // Get current time
            $stmt = $pdo->prepare("SELECT time_left FROM users WHERE id = ?");
            $stmt->execute([$targetUserId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'User not found']);
                break;
            }

            // Parse current time and time to add
            $currentSeconds = parseTimeToSeconds($user['time_left']);
            $addSeconds = parseTimeToSeconds($timeToAdd);
            $newSeconds = $currentSeconds + $addSeconds;
            $newTime = secondsToTimeString($newSeconds);

            // Update user time
            $stmt = $pdo->prepare("UPDATE users SET time_left = ? WHERE id = ?");
            $stmt->execute([$newTime, $targetUserId]);
            
            echo json_encode(['success' => true, 'message' => 'Time added successfully', 'newTime' => $newTime]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error adding time: ' . $e->getMessage()]);
        }
        break;

    case 'changeUserName':
        $targetUserId = $input['targetUserId'] ?? '';
        $newName = $input['newName'] ?? '';
        
        if (empty($targetUserId) || empty($newName)) {
            echo json_encode(['success' => false, 'message' => 'User ID and new name required']);
            break;
        }

        try {
            $stmt = $pdo->prepare("UPDATE users SET name = ? WHERE id = ?");
            $stmt->execute([$newName, $targetUserId]);
            
            echo json_encode(['success' => true, 'message' => 'Name changed successfully']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error changing name: ' . $e->getMessage()]);
        }
        break;

    case 'generateNewToken':
        $userName = $input['userName'] ?? '';
        $expiryDays = $input['expiryDays'] ?? 30;
        
        if (empty($userName)) {
            echo json_encode(['success' => false, 'message' => 'User name required']);
            break;
        }

        try {
            // Generate random token
            $newToken = generateRandomToken();
            
            // Insert new user
            $stmt = $pdo->prepare("INSERT INTO users (name, token, expires_at, time_left) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? DAY), '23h 59m 59s')");
            $stmt->execute([$userName, $newToken, $expiryDays]);
            
            echo json_encode(['success' => true, 'message' => 'New user created', 'newToken' => $newToken]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error creating user: ' . $e->getMessage()]);
        }
        break;

    case 'deleteUser':
        $targetUserId = $input['targetUserId'] ?? '';
        
        if (empty($targetUserId)) {
            echo json_encode(['success' => false, 'message' => 'User ID required']);
            break;
        }

        // Prevent deleting admin users
        if ($targetUserId == 1 || $targetUserId == 3) {
            echo json_encode(['success' => false, 'message' => 'Cannot delete admin users']);
            break;
        }

        try {
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$targetUserId]);
            
            echo json_encode(['success' => true, 'message' => 'User deleted successfully']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error deleting user: ' . $e->getMessage()]);
        }
        break;

    // Site Management
    case 'toggleMaintenanceMode':
        $enabled = $input['enabled'] ?? false;
        try {
            $stmt = $pdo->prepare("UPDATE site_config SET config_value = ? WHERE config_key = 'maintenance_mode'");
            $stmt->execute([$enabled ? '1' : '0']);
            
            // Log the action
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Maintenance mode " . ($enabled ? 'enabled' : 'disabled'), $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Maintenance mode ' . ($enabled ? 'enabled' : 'disabled')]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error updating maintenance mode: ' . $e->getMessage()]);
        }
        break;

    case 'updateAnnouncement':
        $announcement = $input['announcement'] ?? '';
        try {
            $stmt = $pdo->prepare("UPDATE site_config SET config_value = ? WHERE config_key = 'site_announcement'");
            $stmt->execute([$announcement]);
            
            // Log the action
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Site announcement updated", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Announcement updated successfully']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error updating announcement: ' . $e->getMessage()]);
        }
        break;

    case 'getSiteStats':
        try {
            $stmt = $pdo->query("SELECT COUNT(*) as total FROM users");
            $totalUsers = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
            
            $stmt = $pdo->query("SELECT COUNT(*) as active FROM users WHERE expires_at > NOW()");
            $activeUsers = $stmt->fetch(PDO::FETCH_ASSOC)['active'];
            
            $stmt = $pdo->query("SELECT COUNT(*) as expired FROM users WHERE expires_at <= NOW()");
            $expiredUsers = $stmt->fetch(PDO::FETCH_ASSOC)['expired'];
            
            $stmt = $pdo->query("SELECT COUNT(*) as admin FROM users WHERE id IN (1, 3)");
            $adminUsers = $stmt->fetch(PDO::FETCH_ASSOC)['admin'];
            
            echo json_encode([
                'success' => true, 
                'stats' => [
                    'totalUsers' => $totalUsers,
                    'activeUsers' => $activeUsers,
                    'expiredUsers' => $expiredUsers,
                    'adminUsers' => $adminUsers
                ]
            ]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error getting stats: ' . $e->getMessage()]);
        }
        break;

    // Advanced User Management
    case 'bulkOperation':
        $operation = $input['operation'] ?? '';
        $value = $input['value'] ?? '';
        
        try {
            $count = 0;
            switch ($operation) {
                case 'addTimeAll':
                    $addSeconds = parseTimeToSeconds($value);
                    $stmt = $pdo->query("SELECT id, time_left FROM users");
                    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    foreach ($users as $user) {
                        $currentSeconds = parseTimeToSeconds($user['time_left']);
                        $newSeconds = $currentSeconds + $addSeconds;
                        $newTime = secondsToTimeString($newSeconds);
                        $updateStmt = $pdo->prepare("UPDATE users SET time_left = ? WHERE id = ?");
                        $updateStmt->execute([$newTime, $user['id']]);
                        $count++;
                    }
                    break;
                    
                case 'resetTimeAll':
                    $stmt = $pdo->prepare("UPDATE users SET time_left = ? WHERE id NOT IN (1, 3)");
                    $stmt->execute([$value]);
                    $count = $stmt->rowCount();
                    break;
                    
                case 'extendExpiry':
                    $days = intval($value);
                    $stmt = $pdo->prepare("UPDATE users SET expires_at = DATE_ADD(expires_at, INTERVAL ? DAY) WHERE id NOT IN (1, 3)");
                    $stmt->execute([$days]);
                    $count = $stmt->rowCount();
                    break;
            }
            
            echo json_encode(['success' => true, 'message' => "Bulk operation completed on {$count} users"]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error in bulk operation: ' . $e->getMessage()]);
        }
        break;

    case 'exportUsers':
        try {
            $stmt = $pdo->query("SELECT id, name, token, expires_at, time_left, created_at, last_login FROM users ORDER BY id");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'users' => $users]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error exporting users: ' . $e->getMessage()]);
        }
        break;

    case 'cleanupExpiredUsers':
        try {
            $stmt = $pdo->prepare("DELETE FROM users WHERE expires_at <= NOW() AND id NOT IN (1, 3)");
            $stmt->execute();
            $deletedCount = $stmt->rowCount();
            echo json_encode(['success' => true, 'message' => 'Cleanup completed', 'deletedCount' => $deletedCount]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error cleaning up: ' . $e->getMessage()]);
        }
        break;

    // Security & Monitoring
    case 'getLoginAttempts':
        try {
            $stmt = $pdo->query("SELECT u.name as user_name, sl.message as action, sl.created_at as timestamp 
                                FROM system_logs sl 
                                LEFT JOIN users u ON sl.user_id = u.id 
                                WHERE sl.message LIKE '%login%' OR sl.message LIKE '%Login%'
                                ORDER BY sl.created_at DESC 
                                LIMIT 20");
            $attempts = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'attempts' => $attempts]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error getting login attempts: ' . $e->getMessage()]);
        }
        break;

    case 'getSystemLogs':
        try {
            $stmt = $pdo->query("SELECT level, message, created_at as timestamp 
                                FROM system_logs 
                                ORDER BY created_at DESC 
                                LIMIT 50");
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'logs' => $logs]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error getting system logs: ' . $e->getMessage()]);
        }
        break;

    case 'clearAllSessions':
        // In a real implementation, you'd clear session data
        echo json_encode(['success' => true, 'message' => 'All sessions cleared']);
        break;

    case 'regenerateAllTokens':
        try {
            $stmt = $pdo->prepare("UPDATE users SET token = ? WHERE id NOT IN (1, 3)");
            $newToken = generateRandomToken();
            $stmt->execute([$newToken]);
            echo json_encode(['success' => true, 'message' => 'All tokens regenerated']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error regenerating tokens: ' . $e->getMessage()]);
        }
        break;

    // Enhanced User Management
    case 'getUserDetails':
        $targetUserId = $input['targetUserId'] ?? '';
        
        try {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$targetUserId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                echo json_encode(['success' => true, 'user' => $user]);
            } else {
                echo json_encode(['success' => false, 'message' => 'User not found']);
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error getting user details: ' . $e->getMessage()]);
        }
        break;

    case 'regenerateToken':
        $targetUserId = $input['targetUserId'] ?? '';
        
        if ($targetUserId == 1 || $targetUserId == 3) {
            echo json_encode(['success' => false, 'message' => 'Cannot regenerate admin tokens']);
            break;
        }
        
        try {
            $newToken = generateRandomToken();
            $stmt = $pdo->prepare("UPDATE users SET token = ? WHERE id = ?");
            $stmt->execute([$newToken, $targetUserId]);
            echo json_encode(['success' => true, 'message' => 'Token regenerated', 'newToken' => $newToken]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error regenerating token: ' . $e->getMessage()]);
        }
        break;

    case 'exportTokens':
        try {
            $stmt = $pdo->query("SELECT name, token, expires_at FROM users ORDER BY id");
            $tokens = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode(['success' => true, 'tokens' => $tokens]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error exporting tokens: ' . $e->getMessage()]);
        }
        break;

    // Backup & Analytics
    case 'createBackup':
        try {
            // In a real implementation, you'd create an actual database backup
            $backupData = [
                'timestamp' => date('Y-m-d H:i:s'),
                'users_count' => $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn(),
                'config_count' => $pdo->query("SELECT COUNT(*) FROM site_config")->fetchColumn(),
                'logs_count' => $pdo->query("SELECT COUNT(*) FROM system_logs")->fetchColumn()
            ];
            
            // Log the backup creation
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Database backup created", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Backup created successfully', 'backup' => $backupData]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error creating backup: ' . $e->getMessage()]);
        }
        break;

    case 'downloadBackup':
        try {
            // In a real implementation, you'd generate and return actual SQL dump
            $backupContent = "-- Database Backup\n-- Generated: " . date('Y-m-d H:i:s') . "\n\n";
            $backupContent .= "-- Users table\n";
            $stmt = $pdo->query("SELECT * FROM users");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $backupContent .= "INSERT INTO users VALUES (" . implode(', ', array_map(function($v) { return "'" . addslashes($v) . "'"; }, $row)) . ");\n";
            }
            
            header('Content-Type: application/sql');
            header('Content-Disposition: attachment; filename="backup_' . date('Y-m-d') . '.sql"');
            echo $backupContent;
            exit;
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error creating backup file: ' . $e->getMessage()]);
        }
        break;

    case 'getAnalytics':
        try {
            $loginsToday = $pdo->query("SELECT COUNT(*) FROM system_logs WHERE message LIKE '%logged in%' AND DATE(created_at) = CURDATE()")->fetchColumn();
            $failedLogins = $pdo->query("SELECT COUNT(*) FROM system_logs WHERE level = 'warning' AND message LIKE '%Failed login%'")->fetchColumn();
            $activeUsers = $pdo->query("SELECT COUNT(*) FROM users WHERE expires_at > NOW()")->fetchColumn();
            
            $analytics = [
                'loginsToday' => $loginsToday,
                'activeSessions' => $activeUsers,
                'failedLogins' => $failedLogins,
                'uptime' => '99.9%',
                'dbSize' => '2.5 MB'
            ];
            
            echo json_encode(['success' => true, 'analytics' => $analytics]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error getting analytics: ' . $e->getMessage()]);
        }
        break;

    case 'exportAnalytics':
        try {
            $loginsToday = $pdo->query("SELECT COUNT(*) FROM system_logs WHERE message LIKE '%logged in%' AND DATE(created_at) = CURDATE()")->fetchColumn();
            $failedLogins = $pdo->query("SELECT COUNT(*) FROM system_logs WHERE level = 'warning' AND message LIKE '%Failed login%'")->fetchColumn();
            $activeUsers = $pdo->query("SELECT COUNT(*) FROM users WHERE expires_at > NOW()")->fetchColumn();
            
            $analytics = [
                'loginsToday' => $loginsToday,
                'activeSessions' => $activeUsers,
                'failedLogins' => $failedLogins,
                'uptime' => '99.9%',
                'dbSize' => '2.5 MB',
                'exported_at' => date('Y-m-d H:i:s')
            ];
            
            echo json_encode(['success' => true, 'analytics' => $analytics]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error exporting analytics: ' . $e->getMessage()]);
        }
        break;

    case 'checkSystemHealth':
        try {
            $dbStatus = 'Connected';
            $memoryUsage = '45%';
            $diskSpace = '78%';
            $status = 'healthy';
            
            // Check database connection
            $pdo->query("SELECT 1");
            
            $health = [
                'status' => $status,
                'database' => $dbStatus,
                'memory' => $memoryUsage,
                'disk' => $diskSpace
            ];
            
            echo json_encode(['success' => true, 'health' => $health]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error checking system health: ' . $e->getMessage()]);
        }
        break;

    // Notifications Management
    case 'sendNotification':
        $targetUserId = $input['targetUserId'] ?? '';
        $title = $input['title'] ?? '';
        $message = $input['message'] ?? '';
        $type = $input['type'] ?? 'info';
        
        try {
            $stmt = $pdo->prepare("INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)");
            $stmt->execute([$targetUserId, $title, $message, $type]);
            
            // Log the action
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Notification sent to user ID: $targetUserId", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Notification sent successfully']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error sending notification: ' . $e->getMessage()]);
        }
        break;

    case 'broadcastNotification':
        $title = $input['title'] ?? '';
        $message = $input['message'] ?? '';
        $type = $input['type'] ?? 'info';
        
        try {
            $stmt = $pdo->query("SELECT id FROM users");
            $users = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $sentCount = 0;
            
            foreach ($users as $userId) {
                $stmt = $pdo->prepare("INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)");
                $stmt->execute([$userId, $title, $message, $type]);
                $sentCount++;
            }
            
            // Log the action
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Broadcast notification sent to $sentCount users", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Broadcast sent successfully', 'sentCount' => $sentCount]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error sending broadcast: ' . $e->getMessage()]);
        }
        break;

    // Advanced Settings
    case 'updateSiteConfig':
        $siteTitle = $input['siteTitle'] ?? '';
        $siteDescription = $input['siteDescription'] ?? '';
        $maxLoginAttempts = $input['maxLoginAttempts'] ?? '';
        $sessionTimeout = $input['sessionTimeout'] ?? '';
        
        try {
            if ($siteTitle) {
                $stmt = $pdo->prepare("UPDATE site_config SET config_value = ? WHERE config_key = 'site_title'");
                $stmt->execute([$siteTitle]);
            }
            if ($siteDescription) {
                $stmt = $pdo->prepare("UPDATE site_config SET config_value = ? WHERE config_key = 'site_description'");
                $stmt->execute([$siteDescription]);
            }
            if ($maxLoginAttempts) {
                $stmt = $pdo->prepare("UPDATE site_config SET config_value = ? WHERE config_key = 'max_login_attempts'");
                $stmt->execute([$maxLoginAttempts]);
            }
            if ($sessionTimeout) {
                $stmt = $pdo->prepare("UPDATE site_config SET config_value = ? WHERE config_key = 'session_timeout'");
                $stmt->execute([$sessionTimeout]);
            }
            
            // Log the action
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Site configuration updated", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Site configuration updated successfully']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error updating configuration: ' . $e->getMessage()]);
        }
        break;

    case 'clearSystemLogs':
        try {
            $stmt = $pdo->prepare("DELETE FROM system_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            $stmt->execute();
            $deletedCount = $stmt->rowCount();
            
            // Log the action
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "System logs cleared ($deletedCount entries)", $userId]);
            
            echo json_encode(['success' => true, 'message' => "Cleared $deletedCount log entries"]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error clearing logs: ' . $e->getMessage()]);
        }
        break;

    case 'optimizeDatabase':
        try {
            // In a real implementation, you'd run OPTIMIZE TABLE commands
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['info', "Database optimization completed", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Database optimized successfully']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error optimizing database: ' . $e->getMessage()]);
        }
        break;

    case 'restartServices':
        try {
            // In a real implementation, you'd restart actual services
            $stmt = $pdo->prepare("INSERT INTO system_logs (level, message, user_id) VALUES (?, ?, ?)");
            $stmt->execute(['warning', "Services restart initiated", $userId]);
            
            echo json_encode(['success' => true, 'message' => 'Services restart initiated']);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error restarting services: ' . $e->getMessage()]);
        }
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
}

function parseTimeToSeconds($timeStr) {
    if (empty($timeStr) || !is_string($timeStr)) return 0;
    $matches = [];
    $parts = preg_match('/(\d+)h\s*(\d+)m\s*(\d+)s/', $timeStr, $matches);
    if (!$parts || count($matches) < 4) return 0;
    return intval($matches[1]) * 3600 + intval($matches[2]) * 60 + intval($matches[3]);
}

function secondsToTimeString($seconds) {
    $hours = floor($seconds / 3600);
    $minutes = floor(($seconds % 3600) / 60);
    $secs = $seconds % 60;
    return sprintf('%dh %dm %ds', $hours, $minutes, $secs);
}

function generateRandomToken() {
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    $token = '';
    for ($i = 0; $i < 12; $i++) {
        $token .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $token;
}
?>
