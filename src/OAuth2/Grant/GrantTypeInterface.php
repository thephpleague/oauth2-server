<?php

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

interface GrantTypeInterface
{
    public function getIdentifier();

    public function getResponseType();

    public function completeFlow($inputParams = null, $authParams = array());
}
