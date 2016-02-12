<?php
namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * Class ScopeEntity
 * @package League\OAuth2\Server
 */
class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    /**
     * @inheritdoc
     */
    public function jsonSerialize()
    {
        return $this->getIdentifier();
    }
}
