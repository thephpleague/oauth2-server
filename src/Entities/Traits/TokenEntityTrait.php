<?php
namespace League\OAuth2\Server\Entities\Traits;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;

trait TokenEntityTrait
{
    /**
     * @var ScopeEntityInterface[]
     */
    protected $scopes = [];

    /**
     * @var \DateTime
     */
    protected $expiryDateTime;

    /**
     * @var string
     */
    protected $ownerType;

    /**
     * @var string|int
     */
    protected $ownerIdentifier;

    /**
     * @var ClientEntityInterface
     */
    protected $client;

    /**
     * Associate a scope with the token
     * @param \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface $scope
     */
    public function addScope(ScopeEntityInterface $scope)
    {
        $this->scopes[$scope->getIdentifier()] = $scope;
    }

    /**
     * Get an associated scope by the scope's identifier
     * @param string $identifier
     * @return ScopeEntityInterface|null  The scope or null if not found
     */
    public function getScopeWithIdentifier($identifier)
    {
        return (isset($this->scopes[$identifier])) ? $this->scopes[$identifier] : null;
    }

    /**
     * Return an array of scopes associated with the token
     * @return ScopeEntityInterface[]
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Get the token's expiry date time
     * @return \DateTime
     */
    public function getExpiryDateTime()
    {
        return $this->expiryDateTime;
    }

    /**
     * Set the date time when the token expires
     * @param \DateTime $dateTime
     */
    public function setExpiryDateTime(\DateTime $dateTime)
    {
        $this->expiryDateTime = $dateTime;
    }

    /**
     * Set the token's owner
     * @param string     $type       The type of the owner (e.g. "user", "client" or something more specific)
     * @param string|int $identifier The identifier of the owner
     */
    public function setOwner($type, $identifier)
    {
        $this->ownerType = $type;
        $this->ownerIdentifier = $identifier;
    }

    /**
     * Get the token owner's type
     * @return string  The type of owner (e.g. "user", "client" or something more specific)
     */
    public function getOwnerType()
    {
        return $this->ownerType;
    }

    /**
     * Get the token owner's identifier
     * @return string|int
     */
    public function getOwnerIdentifier()
    {
        return $this->ownerIdentifier;
    }

    /**
     * Get the client that the token was issued to
     * @return ClientEntityInterface
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Set the client that the token was issued to
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $client
     */
    public function setClient(ClientEntityInterface $client)
    {
        $this->client = $client;
    }

    /**
     * Has the token expired?
     * @return bool
     */
    public function isExpired()
    {
        return (new \DateTime()) > $this->getExpiryDateTime();
    }
}