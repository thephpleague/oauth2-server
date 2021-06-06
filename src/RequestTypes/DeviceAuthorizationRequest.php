<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

class DeviceAuthorizationRequest
{
    /**
     * The grant type identifier
     *
     * @var string
     */
    protected $grantTypeId;

    /**
     * The client identifier
     *
     * @var ClientEntityInterface
     */
    protected $client;

    /**
     * An array of scope identifiers
     *
     * @var ScopeEntityInterface[]
     */
    protected $scopes = [];

    /**
     * @return string
     */
    public function getGrantTypeId()
    {
        return $this->grantTypeId;
    }

    /**
     * @param string $grantTypeId
     */
    public function setGrantTypeId($grantTypeId)
    {
        $this->grantTypeId = $grantTypeId;
    }

    /**
     * @return ClientEntityInterface
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * @param ClientEntityInterface $client
     */
    public function setClient(ClientEntityInterface $client)
    {
        $this->client = $client;
    }

    /**
     * @return ScopeEntityInterface[]
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }
}
