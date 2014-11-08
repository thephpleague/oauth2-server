<?php

namespace LeagueTests\util;

use League\OAuth2\Server\Util\RedirectUri;

class RedirectUriTest extends \PHPUnit_Framework_TestCase
{
    public function testMake()
    {
        $v1 = RedirectUri::make('https://foobar/', ['foo' => 'bar']);
        $v2 = RedirectUri::make('https://foobar/', ['foo' => 'bar'], '#');
        $v3 = RedirectUri::make('https://foobar/', ['foo' => 'bar', 'bar' => 'foo']);

        $this->assertEquals('https://foobar/?foo=bar', $v1);
        $this->assertEquals('https://foobar/#foo=bar', $v2);
        $this->assertEquals('https://foobar/?foo=bar&bar=foo', $v3);
    }
}
