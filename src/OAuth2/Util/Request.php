<?php

namespace OAuth2\Util;

use OutOfBoundsException;
use InvalidMethodCallException;
use InvalidArgumentException;

class Request implements RequestInterface
{
    protected $get = array();
    protected $post = array();
    protected $cookies = array();
    protected $files = array();
    protected $server = array();
    protected $headers = array();

    public static function buildFromGlobals()
    {
        return new static($_GET, $_POST, $_COOKIE, $_FILES, $_SERVER);
    }

    public function __construct(array $get = array(), array $post = array(), array $cookies = array(), array $files = array(), array $server = array(), $headers = array())
    {
        $this->get = $get;
        $this->post = $post;
        $this->cookies = $cookies;
        $this->files = $files;
        $this->server = $server;

        if (empty($headers)) {
            $this->headers = $this->readHeaders();
        }
    }

    public function get($index = null, $default = null)
    {
        return $this->getPropertyValue('get', $index, $default);
    }

    public function post($index = null, $default = null)
    {
        return $this->getPropertyValue('post', $index, $default);
    }

    public function file($index = null, $default = null)
    {
        return $this->getPropertyValue('files', $index, $default);
    }

    public function cookie($index = null, $default = null)
    {
        return $this->getPropertyValue('cookies', $index, $default);
    }

    public function server($index = null, $default = null)
    {
        return $this->getPropertyValue('server', $index, $default);
    }

    public function header($index = null, $default = null)
    {
        return $this->getPropertyValue('headers', $index, $default);
    }

    protected function readHeaders()
    {
        if (function_exists('getallheaders')) {
            // @codeCoverageIgnoreStart
            $headers = getallheaders();
        } else {
            // @codeCoverageIgnoreEnd
            $headers = array();
            foreach ($this->server() as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') {
                    $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                    $headers[$name] = $value;
                }
            }
        }

        return $headers;
   }

    protected function getPropertyValue($property, $index = null, $default = null)
    {
        if ( ! isset($this->{$property})) {
            throw new InvalidArgumentException("Property '$property' does not exist.");
        }
        if (is_null($index)) {
            return $this->{$property};
        }

        if ( ! array_key_exists($index, $this->{$property})) {
            return $default;
        }

        return $this->{$property}[$index];
    }
}