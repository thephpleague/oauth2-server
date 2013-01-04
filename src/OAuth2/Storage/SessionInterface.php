<?php

namespace OAuth2\Storage;

interface SessionInterface
{
    public function validateAccessToken($access_token);
}
