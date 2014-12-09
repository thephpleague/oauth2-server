<?php
/**
 * OAuth 2.0 scope interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Scope entity interface
 */
interface ScopeInterface extends \JsonSerializable, HydratableInterface
{
    /**
     * Return the scope identifer
     * @return string
     */
    public function getId();

    /**
     * Return the scope's description
     * @return string
     */
    public function getDescription();
}
