<?php
namespace League\OAuth2\Server\Entities\Interfaces;

interface TokenInterface
{
    /**
     * Get the token's identifier
     * @return string
     */
    public function getIdentifier();

    /**
     * Set the token's identifier
     * @param $identifier
     */
    public function setIdentifier($identifier);

    /**
     * Get the token's expiry date time
     * @return \DateTime
     */
    public function getExpiryDateTime();

    /**
     * Set the date time when the token expires
     * @param \DateTime $dateTime
     */
    public function setExpiryDateTime(\DateTime $dateTime);

    /**
     * Set the token's owner
     * @param string     $type       The type of the owner (e.g. "user", "client" or something more specific)
     * @param string|int $identifier The identifier of the owner
     */
    public function setOwner($type, $identifier);

    /**
     * Get the token owner's type
     * @return string  The type of owner (e.g. "user", "client" or something more specific)
     */
    public function getOwnerType();

    /**
     * Get the token owner's identifier
     * @return string|int
     */
    public function getOwnerIdentifier();

    /**
     * Get the client that the token was issued to
     * @return ClientEntityInterface
     */
    public function getClient();

    /**
     * Set the client that the token was issued to
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $client
     */
    public function setClient(ClientEntityInterface $client);

    /**
     * Associate a scope with the token
     * @param \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface $scope
     */
    public function addScope(ScopeEntityInterface $scope);

    /**
     * Get an associated scope by the scope's identifier
     * @param string $identifier
     * @return ScopeEntityInterface|null  The scope or null if not found
     */
    public function getScopeWithIdentifier($identifier);

    /**
     * Return an array of scopes associated with the token
     * @return ScopeEntityInterface[]
     */
    public function getScopes();

    /**
     * Has the token expired?
     * @return bool
     */
    public function isExpired();
}
