<?php

namespace OAuth2\Client;

include_once('Exception.php');

class Client
{
	public function __construct($name, array $options = null)
	{
		if ( ! class_exists($name)) {

			throw new OAuth2\Client\Exception('There is no identity provider called: '.$name);

		}

		return new $name($options);
	}
}