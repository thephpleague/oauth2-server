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
     * Set the client's identifier.
     *
     * @param $identifier
     */
    public function setIdentifier($identifier);

    /**
     * Get the client's name.
     *
     * @return string
     */
    public function getName();

    /**
     * Set the client's name.
     *
     * @param string $name
     */
    public function setName($name);

    /**
     * Set the client's redirect uri.
     *
     * @param string $redirectUri
     */
    public function setRedirectUri($redirectUri);

    /**
     * Returns the registered redirect URI (as a string).
     *
     * Alternatively return an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function getRedirectUri();
}
