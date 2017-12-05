<?php

declare(strict_types = 1);

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

abstract class AbstractJwtAwareRefreshToken implements RefreshTokenEntityInterface {

    use RefreshTokenTrait, CryptTrait;

    /**
     * @inheritdoc
     */
    public function convertToEncryptedRefreshToken()
    {
        return $this->encrypt(
            json_encode(
                [
                    'client_id'        => $this->accessToken->getClient()->getIdentifier(),
                    'refresh_token_id' => $this->getIdentifier(),
                    'access_token_id'  => $this->accessToken->getIdentifier(),
                    'scopes'           => $this->accessToken->getScopes(),
                    'user_id'          => $this->accessToken->getUserIdentifier(),
                    'expire_time'      => $this->getExpiryDateTime()->getTimestamp(),
                ]
            )
        );
    }
}
