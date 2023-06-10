# FilterGuard

FilterGuard is a simple PHP library for data sanitization. It provides methods to sanitize strings, integers, floats, boolean values, arrays, and objects. The library helps protect against common security vulnerabilities such as XSS and SQL injection attacks.

## Usage

Include FilterGuard in your PHP project by including the main library file `FilterGuard.php`. You can then use various methods of the FilterGuard class to sanitize data.

### Examples

```php
<?php
// Including FilterGuard library
require_once 'FilterGuard.php';

// Sanitizing a string
$dirtyString = '<script>alert("XSS attack!");</script>';
$cleanString = FilterGuard::string($dirtyString);
var_dump($cleanString);

// Sanitizing an integer
$dirtyInteger = '123abc';
$cleanInteger = FilterGuard::integer($dirtyInteger);
var_dump($cleanInteger);

// Sanitizing a float
$dirtyFloat = '12.34xyz';
$cleanFloat = FilterGuard::float($dirtyFloat);
var_dump($cleanFloat);

// Sanitizing a boolean value
$dirtyBool = true;
$cleanBool = FilterGuard::bool($dirtyBool);
var_dump($cleanBool);

// Sanitizing an array
$dirtyArray = ['<script>alert("XSS attack!");</script>', '123abc', '12.34xyz'];
$cleanArray = FilterGuard::array($dirtyArray);
var_dump($cleanArray);

// Sanitizing an object
$dirtyObject = (object) ['dirtyString' => '<script>alert("XSS attack!");</script>'];
$cleanObject = FilterGuard::object($dirtyObject);
var_dump($cleanObject);

// Sanitizing an auto
$dirtyValue = '<script>alert("XSS attack!");</script>';
$cleanValue = FilterGuard::auto($dirtyValue);
var_dump($cleanValue);
```

## Contributions

Feel free to contribute to the development of the FilterGuard library by cloning this repository, making changes, and submitting a pull request. You can also report issues or suggest new features through the Issues section.

## Author

Author: Dobren Dragojević 
\
GitHub: https://github.com/ddobren

## License

This library is released under the **MIT License**. Please refer to the LICENSE file for more information about the license.
