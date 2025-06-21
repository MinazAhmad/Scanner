<?php
// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");

// Start session with security settings
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true
]);

// Define constants
define('APP_ROOT', __DIR__);
define('APP_DIR', APP_ROOT . '/app');

// Load configuration
require APP_DIR . '/config.php';

// Handle maintenance mode
if (MAINTENANCE_MODE) {
    http_response_code(503);
    include APP_DIR . '/templates/maintenance.php';
    exit;
}

// Initialize scanner
try {
    require APP_DIR . '/core/SecurityScanner.php';
    $scanner = new SecurityScanner(SECURITY_TOKEN);
    $scanner->loadPlugins(PLUGIN_DIR);
} catch (Throwable $e) {
    error_log("Scanner init failed: " . $e->getMessage());
    http_response_code(500);
    die("System initialization error");
}

// Process requests
try {
    // Handle scan submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan'])) {
        $target = filter_input(INPUT_POST, 'target', FILTER_SANITIZE_URL);
        $domain = parse_url($target, PHP_URL_HOST);
        
        if (!$domain) throw new Exception("Invalid URL format");
        
        $scanner->addAllowedDomain($domain);
        $_SESSION['scan_results'] = $scanner->initiateScan($target);
        header('Location: ?view=results');
        exit;
    }
    
    // Handle exports
    if (isset($_GET['export'])) {
        if (empty($_SESSION['scan_results'])) {
            throw new Exception("No scan data available");
        }
        
        $format = $_GET['export'] === 'csv' ? 'csv' : 'json';
        $scanner->exportResults($_SESSION['scan_results'], $format);
        exit;
    }
    
    // Handle plugin execution
    if (isset($_GET['run_plugin'])) {
        $plugin = $_GET['run_plugin'];
        $target = $_GET['target'] ?? '';
        
        if (!$target) {
            throw new Exception("Target URL required");
        }
        
        $result = $scanner->executePlugin($plugin, $target);
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    }
    
    // Determine view
    $view = 'scan-form';
    if (isset($_GET['view']) && $_GET['view'] === 'results') {
        $view = 'scan-results';
    }
    
    // Prepare data for templates
    $plugins = $scanner->getLoadedPlugins();
    $error = $_SESSION['error'] ?? null;
    unset($_SESSION['error']);
    
    // Render view
    require APP_DIR . "/templates/layout.php";
    
} catch (Throwable $e) {
    $_SESSION['error'] = $e->getMessage();
    header("Location: ?");
    exit;
}