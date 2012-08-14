<?php

namespace Oauth2\Resource;

interface Database
{
	public function validateAccessToken($accessToken);
	
	public function sessionScopes($sessionId);
}