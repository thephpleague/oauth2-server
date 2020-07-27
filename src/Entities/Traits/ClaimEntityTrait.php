<?php
/**
 * @author      Sebastian Kroczek <me@xbug.de>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities\Traits;

trait ClaimEntityTrait
{
    /**
     * @var string
     */
    protected $name;

    /**
     * @var mixed
     */
    protected $value;

    /**
     * Returns the name of the claim
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Returns the claims value
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }
}
