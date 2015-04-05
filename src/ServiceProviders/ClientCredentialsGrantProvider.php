<?php

namespace League\OAuth2\Server\ServiceProviders;

use League\Container\ServiceProvider;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;

class ClientCredentialsGrantServerProvider extends ServiceProvider
{
    protected $provides = ['ClientCredentialsGrant'];

    /**
     * @inheritdoc
     */
    public function register()
    {
        $container = $this->getContainer();

        $container->add('ClientCredentialsGrant', function () use ($container) {
            $grant = new ClientCredentialsGrant(
                $container->get('emitter'),
                $container->get('ClientRepository'),
                $container->get('ScopeRepository'),
                $container->get('AccessTokenRepository')
            );
            return $grant;
        });
    }
}
