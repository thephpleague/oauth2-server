<?php
/**
 * OAuth 2.0 Abstract Server
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\Container\Container;
use League\Container\ContainerAwareInterface;
use League\Container\ContainerAwareTrait;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterTrait;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Resource Server
 */
abstract class AbstractServer implements ContainerAwareInterface, EmitterAwareInterface
{
    use EmitterTrait, ContainerAwareTrait;

    /**
     * The request object
     *
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * Setup the server
     */
    public function __construct()
    {
        $this->setContainer(new Container());
        $this->getContainer()->singleton('emitter', $this->getEmitter());
        $this->getContainer()->addServiceProvider('League\OAuth2\Server\ServiceProviders\ClientCredentialsGrantServerProvider');
    }

    /**
     * Sets the Request Object
     *
     * @param \Symfony\Component\HttpFoundation\Request The Request Object
     *
     * @return self
     * @deprecated
     */
    public function setRequest($request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Gets the Request object. It will create one from the globals if one is not set.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     * @deprecated
     */
    public function getRequest()
    {
        if ($this->request === null) {
            $this->request = Request::createFromGlobals();
        }

        return $this->request;
    }

    /**
     * Add a repository to the server
     *
     * @param RepositoryInterface $repository
     */
    public function addRepository(RepositoryInterface $repository)
    {
        switch ($repository) {
            case ($repository instanceof AccessTokenRepositoryInterface):
                $this->getContainer()->add('AccessTokenRepository', $repository);
                break;
            case ($repository instanceof ClientRepositoryInterface):
                $this->getContainer()->add('ClientRepository', $repository);
                break;
            case ($repository instanceof ScopeRepositoryInterface):
                $this->getContainer()->add('ScopeRepository', $repository);
                break;
            case ($repository instanceof UserRepositoryInterface):
                $this->getContainer()->add('UserRepository', $repository);
                break;
        }
    }
}
