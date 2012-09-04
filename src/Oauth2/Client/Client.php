<?php

namespace Oauth2\Client;

include('Exception.php');
include('Token.php');
include('Provider.php');

/**
 * OAuth2.0
 *
 * @author Phil Sturgeon < @philsturgeon >
 */
class Provider
{

	/**
	 * Create a new provider client.
	 *
	 * @param   string   provider name
	 * @param   array    provider options
	 * @return  OAuth_Provider
	 */
	public function __construct($name, array $options = NULL)
	{
		$name = ucfirst(strtolower($name));

		require_once 'Provider/'.$name.'.php';

		return new $name($options);
	}

}