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
     * Returns the registered redirect URI.
     *
     * @return string
     */
    public function getRedirectUri();
}
