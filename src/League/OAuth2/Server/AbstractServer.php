<?php
/**
 * OAuth 2.0 Abstract Server
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server;

use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Resource Server
 */

abstract class AbstractServer
{
    /**
     * The request object
     *
     * @var Util\RequestInterface
     */
    protected $request;

    /**
     * Storage classes
     * @var array
     */
    protected $storages = [];

    /**
     * Sets the Request Object
     * @param \Symfony\Component\HttpFoundation\Request The Request Object
     * @return self
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }

    /**
     * Gets the Request object. It will create one from the globals if one is not set.
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        if ($this->request === null) {
            $this->request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();
        }

        return $this->request;
    }

    /**
     * Return a storage class
     * @param  string $obj The class required
     * @return Storage\ClientInterface|Storage\ScopeInterface|Storage\SessionInterface
     */
    public function getStorage($obj)
    {
        if (!isset($this->storages[$obj])) {
            throw new ServerException(
                'The `'.$obj.'` storage interface has not been registered with the authorization server'
            );
        }
        return $this->storages[$obj];
    }
}