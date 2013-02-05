<?php

namespace OAuth2\Util;

interface RequestInterface
{

    public static function buildFromGlobals();

    public function __construct(array $get = array(), array $post = array(), array $cookies = array(), array $files = array(), array $server = array(), $headers = array());

    public function get($index = null);

    public function post($index = null);

    public function cookie($index = null);

    public function file($index = null);

    public function server($index = null);

    public function header($index = null);

}
