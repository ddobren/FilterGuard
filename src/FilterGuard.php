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
    public static function sanitizeString(
        $stringValue,
        $encoding = "UTF-8"
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
            case self::isInt($value):
                return self::sanitizeInteger($value);
            case self::isFloat($value):
                return self::sanitizeFloat($value);
            case self::isBool($value):
                return self::sanitizeBoolean($value);
            case is_string($value):
                return self::sanitizeString($value);
            case is_array($value):
                return self::sanitizeArray($value);
            case is_object($value):
                return self::sanitizeObject($value);
            default:
                return $value;
        }
    }
    /**
     * Checks if a value is an integer.
     *
     * @param mixed $value The value to check.
     *
     * @return bool Returns true if the value is an integer, false otherwise.
     */
    private static function isInt($value): bool
    {
        if (is_int($value)) {
            return true;
        }
        if (is_string($value)) {
            $value = trim($value);
            return preg_match('/^[0-9]+$/', $value) === 1;
        }
        return false;
    }

    /**
     * Checks if a value is a float.
     *
     * @param mixed $value The value to check.
     *
     * @return bool Returns true if the value is a float, false otherwise.
     */
    private static function isFloat($value): bool
    {
        if (is_float($value)) {
            return true;
        }
        if (is_string($value)) {
            $value = trim($value);
            return preg_match('/^[0-9]+\.[0-9]+$/', $value) === 1;
        }
        return false;
    }

    /**
     * Checks if a value is a boolean.
     *
     * @param mixed $value The value to check.
     *
     * @return bool Returns true if the value is a boolean, false otherwise.
     */
    private static function isBool($value): bool
    {
        if (is_bool($value)) {
            return true;
        }
        if (is_string($value)) {
            $value = trim($value);
            if (
                preg_match('/^true$/', $value) ||
                preg_match('/^false$/', $value)
            ) {
                return true;
            }
            return false;
        }
        return false;
    }
}
