<?php

class RedirectUri_test extends PHPUnit_Framework_TestCase
{
    function test_make()
    {
        $v1 = League\OAuth2\Server\Util\RedirectUri::make('https://foobar/', array('foo'=>'bar'));
        $v2 = League\OAuth2\Server\Util\RedirectUri::make('https://foobar/', array('foo'=>'bar'), '#');
        $v3 = League\OAuth2\Server\Util\RedirectUri::make('https://foobar/', array('foo'=>'bar', 'bar' => 'foo'));

        $this->assertEquals('https://foobar/?foo=bar', $v1);
        $this->assertEquals('https://foobar/#foo=bar', $v2);
        $this->assertEquals('https://foobar/?foo=bar&bar=foo', $v3);
    }
}
