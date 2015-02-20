<?php

namespace League\OAuth2\Server\Entity;


/**
 * Scope entity class
 */
interface ScopeEntityInterface
{
    /**
     * Return the scope identifer
     *
     * @return string
     */
    public function getId();

    /**
     * Return the scope's description
     *
     * @return string
     */
    public function getDescription();
}