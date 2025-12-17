<?php
// File-based connection status reader
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';
$token = $input['token'] ?? '';

if ($action === 'getConnectionStatus') {
    if (empty($token)) {
        echo json_encode(['success' => false, 'message' => 'Token is required']);
        exit;
    }

    // Read from local file - check multiple possible locations
    $possiblePaths = [
        'connection_status.txt',
        '../tray_app/connection_status.txt',
        '../tray_app/x64/Release/connection_status.txt',
        '../../tray_app/connection_status.txt',
        '../../tray_app/x64/Release/connection_status.txt'
    ];
    
    $content = null;
    foreach ($possiblePaths as $path) {
        if (file_exists($path)) {
            $content = file_get_contents($path);
            break;
        }
    }
    
    if ($content) {
        $data = json_decode($content, true);
        
        if ($data && isset($data['token']) && $data['token'] === $token) {
            echo json_encode([
                'success' => true, 
                'connected' => $data['connected'] ?? false,
                'timestamp' => $data['timestamp'] ?? time()
            ]);
        } else {
            echo json_encode(['success' => true, 'connected' => false]);
        }
    } else {
        echo json_encode(['success' => true, 'connected' => false]);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid action']);
}
?>
