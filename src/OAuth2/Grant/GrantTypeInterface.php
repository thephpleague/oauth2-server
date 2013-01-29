<?php

namespace OAuth2;

interface GrantTypeInterface
{
    public function getIdentifier();

    public function getResponseType();

    public function completeFlow();
}
