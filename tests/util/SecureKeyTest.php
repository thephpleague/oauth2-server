<?php

namespace LeagueTests\Util;

use League\OAuth2\Server\Util\SecureKey;
use \Mockery as M;

class SecureKeyTest extends \PHPUnit_Framework_TestCase
{
	function testMake()
	{
		$v1 = SecureKey::make();
		$v2 = SecureKey::make();
		$v3 = SecureKey::make(50);

		$this->assertEquals(40, strlen($v1));
		$this->assertTrue($v1 !== $v2);
		$this->assertEquals(50, strlen($v3));
	}
}