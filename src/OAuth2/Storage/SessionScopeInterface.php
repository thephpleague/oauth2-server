<?php

namespace OAuth2\Storage;

interface SessionScopeInterface
{
    public function getScopes($session_id);
}
