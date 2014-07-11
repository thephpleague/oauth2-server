<?php

class Secure_Key_test extends PHPUnit_Framework_TestCase
{
    function test_make()
    {
        $v1 = League\OAuth2\Server\Util\SecureKey::make();
        $v2 = League\OAuth2\Server\Util\SecureKey::make();
        $v3 = League\OAuth2\Server\Util\SecureKey::make(50);

        $this->assertEquals(40, strlen($v1));
        $this->assertTrue($v1 !== $v2);
        $this->assertEquals(50, strlen($v3));
    }

    public function test_make_with_different_algorithm()
    {
        $algorithm = $this->getMock('League\OAuth2\Server\Util\KeyAlgorithm\KeyAlgorithmInterface');

        $result = 'dasdsdsaads';
        $algorithm
            ->expects($this->once())
            ->method('make')
            ->with(11)
            ->will($this->returnValue($result))
        ;

        League\OAuth2\Server\Util\SecureKey::setAlgorithm($algorithm);
        $this->assertSame($algorithm, League\OAuth2\Server\Util\SecureKey::getAlgorithm());
        $this->assertEquals($result, League\OAuth2\Server\Util\SecureKey::make(11));
    }
}
