<?php

namespace LeagueTests\util;

use \League\OAuth2\Server\Util\SecureKey;

class SecureKeyTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerate()
    {
        $v1 = SecureKey::generate();
        $v2 = SecureKey::generate();
        $v3 = SecureKey::generate(50);

        $this->assertEquals(40, strlen($v1));
        $this->assertTrue($v1 !== $v2);
        $this->assertEquals(50, strlen($v3));
    }

    public function testGenerateWithDifferentAlgorithm()
    {
        $algorithm = $this->getMock('League\OAuth2\Server\Util\KeyAlgorithm\KeyAlgorithmInterface');

        $result = 'dasdsdsaads';
        $algorithm
            ->expects($this->once())
            ->method('generate')
            ->with(11)
            ->will($this->returnValue($result))
        ;

        SecureKey::setAlgorithm($algorithm);
        $this->assertSame($algorithm, SecureKey::getAlgorithm());
        $this->assertEquals($result, SecureKey::generate(11));
    }
}
