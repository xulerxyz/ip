<?php

namespace Nigel\Ip;

class IpAddress
{

    /**
     * Get IP Address
     * @return string
     */
    public function getIp()
    {
        // Start with HTTP_X_FORWARDED_FOR for reverse proxy setups
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach ($ipList as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip; // Return the first public IP found
                }
            }
        }

        // Fall back to other headers if X-Forwarded-For is not available or valid
        foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'] as $key) {
            if (!empty($_SERVER[$key]) && filter_var($_SERVER[$key], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $_SERVER[$key];
            }
        }

        // Default to localhost if no valid IP found
        return "127.0.0.1";
    }


    /**
     * Check if IP address is in range
     * @param mixed $ip
     * @param mixed $range
     * @return bool
     */
    private function ipInRange($ip, $range)
    {
        list($subnet, $bits) = explode('/', $range);

        // Validate IP subnet format
        if (!filter_var($subnet, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Validate bits
        if (!is_numeric($bits) || $bits < 0 || $bits > 32) {
            return false;
        }

        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask; // Calculate the network address
        return ($ip & $mask) == $subnet;
    }

    /**
     * Validate IP address
     * @param string $ip
     * @return bool
     */
    function validateIPAddress(string $ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        return true;
    }

    /**
     * Check if the visitor's IP address is within any of the allowed ranges
     * @param array $allowedRanges
     * @param string $ip
     * @return bool
     */
    function checkVisitorIpInRange(array $allowedRanges, string $ip)
    {
        foreach ($allowedRanges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }
        return false;
    }


}