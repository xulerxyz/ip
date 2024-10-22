# IP Address Helper Service

Package to get visitor IP address and check if visitor's IP address is in your range of allowed addresses

###  Install latest with Composer

```bash
composer require nigel/ip
```

### Full example

```php

<?php

use Nigel\Ip\IpAddress;

require_once __DIR__ . '/vendor/autoload.php';

header('Content-type: application/json');

//Initialize IpAddress
$ipService = new IpAddress();

// Define your IP address ranges
$allowedRanges = [
    '127.0.0.1/18',
];

// Get the visitor's IP address
$visitorIp = $ipService->getIp();

// Validate IP address format
if ($ipService->validateIPAddress($visitorIp) === false) {
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid Ip Address'
    ]);
}

// Check if the visitor's IP address is within any of the allowed ranges
if ($ipService->checkVisitorIpInRange($allowedRanges, $visitorIp)) {
    echo json_encode([
        'status' => 'success',
        'message' => 'Valid IP Address'
    ]);
} else {
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid IP Address'
    ]);
}

```