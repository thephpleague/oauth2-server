<?php

class Secure_Key_test extends PHPUnit_Framework_TestCase
{
	function test_make()
	{
		$v1 = OAuth2\Util\SecureKey::make();
		$v2 = OAuth2\Util\SecureKey::make();
		$v3 = OAuth2\Util\SecureKey::make(50);

		$this->assertEquals(40, strlen($v1));
		$this->assertTrue($v1 !== $v2);
		$this->assertEquals(50, strlen($v3));
	}
}