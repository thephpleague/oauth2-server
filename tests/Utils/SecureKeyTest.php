<?php

namespace LeagueTests\Utils;

use League\OAuth2\Server\Utils\SecureKey;

class SecureKeyTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerate()
    {
        $this->assertTrue(is_string(SecureKey::generate()));
    }
}
