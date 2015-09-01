<?php

namespace League\OAuth2\Server\ServerInterface;

use League\OAuth2\Server\Grant\GrantTypeInterface;

interface GrantServer
{
    /**
     * Enable support for a grant
     *
     * @param GrantTypeInterface $grantType  A grant class which conforms to Interface/GrantTypeInterface
     * @param null|string        $identifier An identifier for the grant (autodetected if not passed)
     *
     * @return self
     */
    public function addGrantType(GrantTypeInterface $grantType, $identifier);

    /**
     * Check if a grant type has been enabled
     *
     * @param string $identifier The grant type identifier
     *
     * @return boolean Returns "true" if enabled, "false" if not
     */
    public function hasGrantType($identifier);

    /**
     * Return a grant type class
     *
     * @param string $grantType The grant type identifier
     *
     * @return GrantTypeInterface
     *
     * @throws
     */
    public function getGrantType($grantType);

}