<?php

namespace League\OAuth2\Server\Entities\Interfaces;

interface ClientEntityInterface
{
    /**
     * Get the client's identifier.
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Get the client's name.
     *
     * @return string
     */
    public function getName();

    /**
     * Get the hashed client secret
     *
     * @return string
     */
    public function getSecret();

    /**
     * Returns the registered redirect URI.
     *
     * @return string
     */
    public function getRedirectUri();

    /**
     * Returns true if the client is capable of keeping it's secrets secret.
     *
     * @return bool
     */
    public function canKeepASecret();
}
