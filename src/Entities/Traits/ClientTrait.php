<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities\Traits;

trait ClientTrait
{
    /**
     * @var null|string
     */
    protected $name;

    /**
     * @var null|string|string[]
     */
    protected $redirectUri;

    /**
     * Get the client's name.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set the client's name.
     *
     * @param string $name
     */
    public function setName($name)
    {
        $this->name = $name;
    }

    /**
     * Returns the registered redirect URI (as a string).
     *
     * Alternatively return an indexed array of redirect URIs.
     *
     * @return string|string[]
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * Sets the registered redirect URI (as a string).
     *
     * Alternatively set an indexed array of redirect URIs.
     *
     * @param string|string[] $uri
     */
    public function setRedirectUri($uri)
    {
        $this->redirectUri = $uri;
    }
}
