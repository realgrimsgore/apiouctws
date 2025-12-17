<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

require_once '../config/database.php';

switch ($action) {
    case 'getSiteConfig':
        try {
            $stmt = $pdo->query("SELECT config_key, config_value FROM site_config");
            $configs = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
            echo json_encode(['success' => true, 'config' => $configs]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error getting config: ' . $e->getMessage()]);
        }
        break;

    case 'checkMaintenance':
        try {
            $stmt = $pdo->prepare("SELECT config_value FROM site_config WHERE config_key = 'maintenance_mode'");
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $isMaintenance = $result ? (bool)$result['config_value'] : false;
            
            $stmt = $pdo->prepare("SELECT config_value FROM site_config WHERE config_key = 'site_announcement'");
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $announcement = $result ? $result['config_value'] : '';
            
            echo json_encode([
                'success' => true, 
                'maintenance_mode' => $isMaintenance,
                'announcement' => $announcement
            ]);
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'message' => 'Error checking maintenance: ' . $e->getMessage()]);
        }
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
}
?>
