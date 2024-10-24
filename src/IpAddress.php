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
        foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'] as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        // fall back to localhost/127.0.0.1 when IP Address is not found
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