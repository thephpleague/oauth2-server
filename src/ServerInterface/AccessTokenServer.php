<?php

namespace League\OAuth2\Server\ServerInterface;

interface AccessTokenServer
{
    /**
     * Get the TTL for an access token
     *
     * @return int The TTL
     */
    public function getAccessTokenTTL();

    /**
     * Set the TTL for an access token
     *
     * @param int $accessTokenTTL The new TTL
     *
     * @return self
     */
    public function setAccessTokenTTL($accessTokenTTL);

    /**
     * Issue an access token
     *
     * @return array Authorise request parameters
     *
     * @throws
     */
    public function issueAccessToken();
}