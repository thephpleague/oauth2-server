<?php
/**
 * Created by PhpStorm.
 * User: jderay
 * Date: 3/11/14
 * Time: 12:31 PM
 */

class Default_Algorithm_test extends PHPUnit_Framework_TestCase
{
    public function test_make()
    {
        $algorithm = new League\OAuth2\Server\Util\KeyAlgorithm\DefaultAlgorithm();
        $v1 = $algorithm->make();
        $v2 = $algorithm->make();
        $v3 = $algorithm->make(50);

        $this->assertEquals(40, strlen($v1));
        $this->assertTrue($v1 !== $v2);
        $this->assertEquals(50, strlen($v3));
    }
} 