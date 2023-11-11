<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\Event\Event;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;

class AuthCodeEvent extends Event
{
    const AUTH_CODE_ISSUED = 'auth_code.issued';

    /**
     * @var AuthCodeEntityInterface
     */
    private $authCode;

    public function __construct(AuthCodeEntityInterface $authCode)
    {
        parent::__construct(self::AUTH_CODE_ISSUED);
        $this->authCode = $authCode;
    }

    /**
     * @return AuthCodeEntityInterface
     *
     * @codeCoverageIgnore
     */
    public function getAuthCode()
    {
        return $this->authCode;
    }
}
