<?php
/**
 * OAuth 2.0 Request class
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Util;

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
        } else {
            $this->headers = $this->normalizeHeaders($headers);
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
        if (function_exists('apache_request_headers')) {
            // @codeCoverageIgnoreStart
            $headers = apache_request_headers();
        } elseif (function_exists('http_get_request_headers')) {
            $headers = http_get_request_headers();
        } else {
            // @codeCoverageIgnoreEnd
            $headers = array();
            foreach ($this->server() as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') {
                    // HTTP_FOO_BAR becomes FOO-BAR
                    $name = str_replace(array('HTTP_', '_'), array('', '-'), $name);
                    $headers[$name] = $value;
                }
            }
        }

        return $this->normalizeHeaders($headers);
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

    /**
     * Takes all of the headers and normalizes them in a canonical form.
     *
     * @param  array  $headers The request headers.
     * @return array           An arry of headers with the header name normalized
     */
    protected function normalizeHeaders(array $headers)
    {
        $normalized = array();
        foreach ($headers as $key => $value) {
            $normalized[ucfirst($this->normalizeKey($key))] = $value;
        }

        return $normalized;
    }

    /**
     * Transform header name into canonical form
     *
     * Taken from the Slim codebase...
     *
     * @param  string $key
     * @return string
     */
    protected function normalizeKey($key)
    {
        $key = strtolower($key);
        $key = str_replace(array('-', '_'), ' ', $key);
        $key = preg_replace('#^http #', '', $key);
        $key = ucwords($key);
        $key = str_replace(' ', '-', $key);

        return $key;
    }
}
