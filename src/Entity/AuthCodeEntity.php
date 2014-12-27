<?php
/**
 * OAuth 2.0 Auth code entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Auth code entity class
 */
class AuthCodeEntity extends AbstractTokenEntity implements AuthCodeInterface
{
    /**
     * Redirect URI
     *
     * @var string
     */
    protected $redirectUri = '';

    /**
     * {@inheritDoc}
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * {@inheritDoc}
     */
    public function generateRedirectUri($state = null, $queryDelimeter = '?')
    {
        $uri = $this->getRedirectUri();
        $uri .= (strstr($this->getRedirectUri(), $queryDelimeter) === false) ? $queryDelimeter : '&';

        return $uri . http_build_query([
            'code'  => $this->getId(),
            'state' => $state,
        ]);
    }

    /**
     * {@inheritDoc}
     */
    public function getSession()
    {
        if ($this->session instanceof SessionInterface) {
            return $this->session;
        }

        $this->session = $this->server->getSessionStorage()->getByAuthCode($this);

        return $this->session;
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes()
    {
        if ($this->scopes === null) {
            $this->scopes = $this->formatScopes(
                $this->server->getAuthCodeStorage()->getScopes($this)
            );
        }

        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function save()
    {
        $this->server->getAuthCodeStorage()->create(
            $this->getId(),
            $this->getExpireTime(),
            $this->getSession()->getId(),
            $this->getRedirectUri()
        );

        // Associate the scope with the token
        foreach ($this->getScopes() as $scope) {
            $this->server->getAuthCodeStorage()->associateScope($this, $scope);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function expire()
    {
        $this->server->getAuthCodeStorage()->delete($this);
    }
}
