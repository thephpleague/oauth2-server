<?php

namespace OAuth2;

class Server
{
    protected $scopeDelimeter = ',';

    protected $expiresIn = 3600;

    protected $responseTypes = array(
        'code'
    );

    protected $storages = array();

    protected $grantTypes = array();

    public function __construct($storage)
    {

    }

    public function addGrantType(GrantTypeInterface $grant_type, $identifier = null)
    {
        if (is_null($identifier)) {
            $identifier = $grant_type->getIdentifier();
        }
        $this->grantTypes[$identifier] = $grant_type;
    }

    public function setScopeDelimeter($scope_delimeter)
    {
        $this->scopeDelimeter = $scope_delimeter;
    }

    public function setExpiresIn($expires_in)
    {
        $this->expiresIn = $expires_in;
    }

}
