<?php

namespace League\OAuth2\Server\Entity;


/**
 * Auth Code entity class
 */
interface AuthCodeEntityInterface
{
    /**
     * Set the redirect URI for the authorization request
     *
     * @param string $redirectUri
     *
     * @return self
     */
    public function setRedirectUri($redirectUri);

    /**
     * Get the redirect URI
     *
     * @return string
     */
    public function getRedirectUri();

    /**
     * Generate a redirect URI
     *
     * @param string $state The state parameter if set by the client
     * @param string $queryDelimeter The query delimiter ('?' for auth code grant, '#' for implicit grant)
     *
     * @return string
     */
    public function generateRedirectUri($state = null, $queryDelimeter = '?');

    /**
     * Get session
     *
     * @return \League\OAuth2\Server\Entity\SessionEntity
     */
    public function getSession();

    /**
     * Return all scopes associated with the session
     *
     * @return \League\OAuth2\Server\Entity\ScopeEntity[]
     */
    public function getScopes();

    /**
     * {@inheritdoc}
     */
    public function save();

    /**
     * {@inheritdoc}
     */
    public function expire();
}