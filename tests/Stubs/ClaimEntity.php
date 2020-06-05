<?php


namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\ClaimEntityInterface;

class ClaimEntity implements ClaimEntityInterface
{
    private $name;
    private $value;

    public function __construct($name, $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function jsonSerialize()
    {
        return ['name' => $this->name, 'value' => $this->value];
    }
}