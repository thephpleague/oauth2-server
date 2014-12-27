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
interface ScopeInterface extends \JsonSerializable
{
    /**
     * Return the scope identifier
     * @return string
     */
    public function getId();

    /**
     * Set the scope identifier
     * @param $id
     * @return self
     */
    public function setId($id);

    /**
     * Return the scope's description
     * @return string
     */
    public function getDescription();

    /**
     * Set the scope description
     * @param $description
     * @return self
     */
    public function setDescription($description);
}
