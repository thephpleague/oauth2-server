<?php

namespace League\OAuth2\Server\ServiceProviders;

use League\Container\ServiceProvider;
use League\OAuth2\Server\Grant\PasswordGrant;

class PasswordGrantProvider extends ServiceProvider
{
    protected $provides = ['PasswordGrant'];

    /**
     * @inheritdoc
     */
    public function register()
    {
        $container = $this->getContainer();

        $container->add('PasswordGrant', function () use ($container) {

            $refreshTokenRepository = null;
            if ($container->isRegistered('RefreshTokenRepository')) {
                $refreshTokenRepository = $container->get('RefreshTokenRepository');
            }

            $grant = new PasswordGrant(
                $container->get('emitter'),
                $container->get('ClientRepository'),
                $container->get('ScopeRepository'),
                $container->get('AccessTokenRepository'),
                $container->get('UserRepository'),
                $refreshTokenRepository
            );
            return $grant;
        });
    }
}
