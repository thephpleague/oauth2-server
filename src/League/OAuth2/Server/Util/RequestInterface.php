<?php
/**
 * OAuth 2.0 Request class interface
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Util;

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
