<?php

namespace League\OAuth2\Server\Entity;


/**
 * Access token entity class
 */
interface AccessTokenEntityInterface extends AbstractTokenEntityInterface
{
    /**
     * Get session
     *
     * @return \League\OAuth2\Server\Entity\SessionEntity
     */
    public function getSession();

    /**
     * Check if access token has an associated scope
     *
     * @param string $scope Scope to check
     *
     * @return bool
     */
    public function hasScope($scope);

    /**
     * Return all scopes associated with the access token
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