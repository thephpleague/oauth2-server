<?php

namespace League\OAuth2\Server\Util;

interface TokenGeneratorInterface
{
	public function generateAccessToken();

	public function generateRefreshToken();
}
