<?php
namespace Codeception\Module;

// here you can define custom actions
// all public methods declared in helper class will be available in $I

class AuthHelper extends \Codeception\Module
{
    function seeJsonKeyExists($key)
    {
        $json = $this->getModule('REST')->grabResponse();
        $array = json_decode($json);
        $this->assertTrue(array_key_exists($key, $array));
    }

    function seeJsonKeyDoesNotExists($key)
    {
        $json = $this->getModule('REST')->grabResponse();
        $array = json_decode($json);
        $this->assertFalse(array_key_exists($key, $array));
    }
}