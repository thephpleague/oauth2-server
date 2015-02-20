<?php

namespace League\OAuth2\Server\Entity;


/**
 * Client entity class
 */
interface ClientEntityInterface
{
    /**
     * Return the client identifier
     *
     * @return string
     */
    public function getId();

    /**
     * Return the client secret
     *
     * @return string
     */
    public function getSecret();

    /**
     * Get the client name
     *
     * @return string
     */
    public function getName();

    /**
     * Returnt the client redirect URI
     *
     * @return string
     */
    public function getRedirectUri();
}