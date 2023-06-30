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
    public static function sanitizeString($stringValue, string $encoding = "UTF-8"): string
    {
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
     * @param mixed $integerValue The integer value to sanitize.
     * @return int              The sanitized integer value.
     */
    public static function sanitizeInteger($integerValue): int
    {
        $integerValue = intval($integerValue);
        $integerValue = filter_var($integerValue, FILTER_SANITIZE_NUMBER_INT);
        return (int) $integerValue;
    }

    /**
     * Sanitizes a float value.
     *
     * @param mixed $floatValue The float value to sanitize.
     * @return float           The sanitized float value.
     */
    public static function sanitizeFloat($floatValue): float
    {
        $floatValue = floatval($floatValue);
        $floatValue = filter_var(
            $floatValue,
            FILTER_SANITIZE_NUMBER_FLOAT,
            FILTER_FLAG_ALLOW_FRACTION
        );
        return (float) $floatValue;
    }

    /**
     * Sanitizes a boolean value.
     *
     * @param mixed $boolValue The boolean value to sanitize.
     * @return bool          The sanitized boolean value.
     */
    public static function sanitizeBoolean($boolValue): bool
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
     * Sanitizes an array value recursively.
     *
     * @param mixed $arrayValue The array value to sanitize.
     * @return array            The sanitized array value.
     */
    public static function sanitizeArray($arrayValue): array
    {
        $sanitizedArray = [];
        foreach ($arrayValue as $key => $value) {
            if (is_array($value)) {
                $sanitizedArray[$key] = self::sanitizeArray($value);
            } else {
                $sanitizedArray[$key] = self::sanitizeAuto($value);
            }
        }
        return $sanitizedArray;
    }

    /**
     * Sanitizes an object value recursively.
     *
     * @param mixed $objectValue The object value to sanitize.
     * @return object             The sanitized object value.
     */
    public static function sanitizeObject($objectValue): object
    {
        $objectValue = (array) $objectValue;
        $objectValue = array_map(function ($value) {
            return self::sanitizeAuto($value);
        }, $objectValue);
        return (object) $objectValue;
    }

    /**
     * Automatically sanitizes a value based on its type.
     *
     * @param mixed $value The value to sanitize.
     * @return mixed       The sanitized value.
     */
    public static function sanitizeAuto($value): mixed
    {
        switch (true) {
            case is_string($value):
                return FilterGuard::sanitizeString($value);
            case is_int($value):
                return FilterGuard::sanitizeInteger($value);
            case is_float($value):
                return FilterGuard::sanitizeFloat($value);
            case is_bool($value):
                return FilterGuard::sanitizeBoolean($value);
            case is_array($value):
                return FilterGuard::sanitizeArray($value);
            case is_object($value):
                return FilterGuard::sanitizeObject($value);
            default:
                return $value;
        }
    }
}
