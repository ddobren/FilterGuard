<?php

declare(strict_types=1);

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

namespace FilterGuard;

class FilterGuard
{
    /**
     * Sanitizes a string value.
     *
     * @param string $stringValue The string value to sanitize.
     * @param string $encoding    (optional) The character encoding to use. Defaults to "UTF-8".
     * @return string             The sanitized string value.
     */
    public static function string(
        string $stringValue,
        string $encoding = "UTF-8"
    ): string {
        $stringValue = strval($stringValue);
        $stringValue = strip_tags($stringValue);
        $stringValue = htmlspecialchars($stringValue, ENT_QUOTES, $encoding);
        $stringValue = trim($stringValue);
        $stringValue = filter_var($stringValue, FILTER_SANITIZE_ADD_SLASHES);
        return $stringValue;
    }
    /**
     * Sanitizes an integer value.
     *
     * @param int $integerValue The integer value to sanitize.
     * @return int              The sanitized integer value.
     */
    public static function integer(int $integerValue): int
    {
        $integerValue = intval($integerValue);
        $integerValue = filter_var($integerValue, FILTER_SANITIZE_NUMBER_INT);
        return $integerValue;
    }
    /**
     * Sanitizes a float value.
     *
     * @param float $floatValue The float value to sanitize.
     * @return float            The sanitized float value.
     */
    public static function float(float $floatValue): float
    {
        $floatValue = floatval($floatValue);
        $floatValue = filter_var(
            $floatValue,
            FILTER_SANITIZE_NUMBER_FLOAT,
            FILTER_FLAG_ALLOW_FRACTION
        );
        return $floatValue;
    }
    /**
     * Sanitizes a boolean value.
     *
     * @param bool $boolValue The boolean value to sanitize.
     * @return bool           The sanitized boolean value.
     */
    public static function bool(bool $boolValue): bool
    {
        $boolValue = boolval($boolValue);
        $boolValue = filter_var(
            $boolValue,
            FILTER_VALIDATE_BOOLEAN,
            FILTER_NULL_ON_FAILURE
        );
        return $boolValue;
    }
    /**
     * Sanitizes an array value.
     *
     * @param array $arrayValue The array value to sanitize.
     * @return array            The sanitized array value.
     */
    public static function array(array $arrayValue): array
    {
        $sanitizedArray = [];
        foreach ($arrayValue as $key => $value) {
            if (is_array($value)) {
                $sanitizedArray[$key] = self::array($value);
            } else {
                $sanitizedArray[$key] = self::auto($value);
            }
        }
        return $sanitizedArray;
    }
    /**
     * Sanitizes an object value.
     *
     * @param object $objectValue The object value to sanitize.
     * @return object             The sanitized object value.
     */
    public static function object(object $objectValue): object
    {
        $objectValue = (array) $objectValue;
        $objectValue = array_map(function ($value) {
            return self::auto($value);
        }, $objectValue);
        return (object) $objectValue;
    }
    /**
     * Automatically determines the type of the value and applies the corresponding sanitization method.
     *
     * @param mixed $valueType The value to sanitize.
     * @return mixed           The sanitized value.
     */
    public static function auto(mixed $valueType): mixed
    {
        if (is_string($valueType)) {
            return FilterGuard::string($valueType);
        } elseif (is_int($valueType)) {
            return FilterGuard::integer($valueType);
        } elseif (is_float($valueType)) {
            return FilterGuard::float($valueType);
        } elseif (is_bool($valueType)) {
            return FilterGuard::bool($valueType);
        } elseif (is_array($valueType)) {
            return FilterGuard::array($valueType);
        } elseif (is_object($valueType)) {
            return FilterGuard::object($valueType);
        }
    }
}
