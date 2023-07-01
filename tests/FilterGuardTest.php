<?php

namespace FilterGuard\Tests;

use PHPUnit\Framework\TestCase;
use FilterGuard\FilterGuard;

class FilterGuardTest extends TestCase
{
    /**
     * @test
     */
    public function testStringFunc(): void
    {
        // test 1
        $dirtyStr = '<script>alert(\'Hacked\')</script>';
        $result = FilterGuard::sanitizeString($dirtyStr);
        $expected = "alert(&#039;Hacked&#039;)";
        $this->assertSame($expected, $result);
        // test 2
        $dirtyStr = "<b>HACK</b>";
        $result = FilterGuard::sanitizeString($dirtyStr);
        $expected = "HACK";
        $this->assertSame($expected, $result);
    }
    /**
     * @test
     */
    public function testIntegerFunc(): void
    {
        // test 1
        $dirtyInt = "7363";
        $result = FilterGuard::sanitizeInteger($dirtyInt);
        $expected = 7363;
        $this->assertSame($expected, $result);
        // test 2
        $dirtyInt = "63.73";
        $result = FilterGuard::sanitizeInteger($dirtyInt);
        $expected = 63;
        $this->assertSame($expected, $result);
    }
    /**
     * @test
     */
    public function testFloatFunc(): void
    {
        // test 1
        $dirtyFloat = "736.73";
        $result = FilterGuard::sanitizeFloat($dirtyFloat);
        $expected = 736.73;
        $this->assertSame($expected, $result);
        // test 2
        $dirtyFloat = "736";
        $result = FilterGuard::sanitizeFloat($dirtyFloat);
        $expected = 736.0;
        $this->assertSame($expected, $result);
        // test 3
        $dirtyFloat = "10.xyz";
        $result = FilterGuard::sanitizeFloat($dirtyFloat);
        $expected = 10.0;
        $this->assertSame($expected, $result);
    }
    /**
     * @test
     */
    public function testBooleanFunc(): void
    {
        // test 1
        $dirtyBool = "true";
        $result = FilterGuard::sanitizeBoolean($dirtyBool);
        $expected = true;
        $this->assertSame($expected, $result);
        // test 2
        $dirtyBool = 1;
        $result = FilterGuard::sanitizeBoolean($dirtyBool);
        $expected = true;
        $this->assertSame($expected, $result);
        // test 3
        $dirtyBool = 0;
        $result = FilterGuard::sanitizeBoolean($dirtyBool);
        $expected = false;
        $this->assertSame($expected, $result);
        // test 4
        $dirtyBool = false;
        $result = FilterGuard::sanitizeBoolean($dirtyBool);
        $expected = false;
        $this->assertSame($expected, $result);
    }
    /**
     * @test
     */
    public function testArrayFunc(): void
    {
        $dirtyArray = [
            "key" => "<b>ATTACK</b>",
            "xss" => '<script>alert(\'XSS\')</script>',
        ];
        $result = FilterGuard::sanitizeArray($dirtyArray);
        $expected = [
            "key" => "ATTACK",
            "xss" => "alert(&#039;XSS&#039;)",
        ];
        $this->assertSame($expected, $result);
    }

    /**
     * @test
     */
    public function testAutoFunc(): void
    {
        // test 1
        $dirtyArray = [
            "key" => "<b>ATTACK</b>",
            "xss" => '<script>alert(\'XSS\')</script>',
            "int" => "7335",
            "float" => "67.09",
            "bool" => "true",
        ];
        $result = FilterGuard::sanitizeAuto($dirtyArray);
        $expected = [
            "key" => "ATTACK",
            "xss" => "alert(&#039;XSS&#039;)",
            "int" => 7335,
            "float" => 67.09,
            "bool" => true,
        ];
        $this->assertSame($expected, $result);
        // test 2
        $dirtyStr = "<b>HACK</b>";
        $result = FilterGuard::sanitizeAuto($dirtyStr);
        $expected = "HACK";
        $this->assertSame($expected, $result);
        // test 3
        $dirtyInt = "7226";
        $result = FilterGuard::sanitizeAuto($dirtyInt);
        $expected = 7226;
        $this->assertSame($expected, $result);
        // test 4
        $dirtyFloat = "7226.99";
        $result = FilterGuard::sanitizeAuto($dirtyFloat);
        $expected = 7226.99;
        $this->assertSame($expected, $result);
        // test 5
        $dirtyFloat = "true";
        $result = FilterGuard::sanitizeAuto($dirtyFloat);
        $expected = true;
        $this->assertSame($expected, $result);
    }
}
