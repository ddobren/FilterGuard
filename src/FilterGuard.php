<?php

/**
 * FilterGuard - PHP data sanitization library
 *
 * Author: [Dobren Dragojević]
 * GitHub: [https://github.com/ddobren/FilterGuard]
 *
 * Description: FilterGuard is a simple PHP library for sanitizing data.
 * It provides methods to sanitize strings, integers, floats, booleans, arrays, and objects.
 * The library helps protect against common security vulnerabilities such as XSS and SQL injection.
 */

class FilterGuard
{
    public static function string(string $stringValue): string
    {
        $stringValue = strval($stringValue);
        $stringValue = strip_tags($stringValue);
        $stringValue = htmlspecialchars($stringValue, ENT_QUOTES, "UTF-8");
        $stringValue = trim($stringValue);
        $stringValue = filter_var($stringValue, FILTER_SANITIZE_ADD_SLASHES);
        return $stringValue;
    }

    public static function integer(int $integerValue): int
    {
        $integerValue = intval($integerValue);
        $integerValue = filter_var($integerValue, FILTER_SANITIZE_NUMBER_INT);
        return $integerValue;
    }

    public static function float(float $floatValue): float
    {
        $floatValue = floatval($floatValue);
        $floatValue = filter_var($floatValue, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        return $floatValue;
    }

    public static function bool(bool $boolValue): bool
    {
        $boolValue = boolval($boolValue);
        $boolValue = filter_var($boolValue, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        return $boolValue;
    }

    public static function array(array $arrayValue): array
    {
        $sanitizedArray = array();
        foreach ($arrayValue as $key => $value) {
            if (is_array($value)) {
                $sanitizedArray[$key] = self::array($value);
            } else {
                $sanitizedArray[$key] = self::auto($value);
            }
        }
        return $sanitizedArray;
    }

    public static function object(object $objectValue): object
    {
        $objectValue = (array) $objectValue;
        $objectValue = array_map(function ($value) {
            return self::auto($value);
        }, $objectValue);
        return (object) $objectValue;
    }

    public static function auto($valueType)
    {
        if (is_string($valueType)) {
            return FilterGuard::string($valueType);
        } elseif (is_int($valueType)) {
            return FilterGuard::integer($valueType);
        } elseif (is_float($valueType)) {
            return FilterGuard::float($valueType);
        } elseif (is_bool($valueType)) {
            return FilterGuard::bool($valueType);
        } else if (is_array($valueType)) {
            return FilterGuard::array($valueType);
        } else if (is_object($valueType)) {
            return FilterGuard::object($valueType);
        }
    }
}
