<?php
/**
 * OAuth 2.0 session owner event
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Event;

use League\Event\AbstractEvent;
use League\OAuth2\Server\Entity\SessionEntity;

class SessionOwnerEvent extends AbstractEvent
{
    /**
     * Session entity
     *
     * @var \League\OAuth2\Server\Entity\SessionEntity
     */
    private $session;

    /**
     * Init the event with a session
     *
     * @param \League\OAuth2\Server\Entity\SessionEntity $session
     */
    public function __construct(SessionEntity $session)
    {
        $this->session = $session;
    }

    /**
     * The name of the event
     *
     * @return string
     */
    public function getName()
    {
        return 'session.owner';
    }

    /**
     * Return session
     *
     * @return \League\OAuth2\Server\Entity\SessionEntity
     */
    public function getSession()
    {
        return $this->session;
    }
}
