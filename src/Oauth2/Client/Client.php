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
class Client {

	/**
	 * Create a new provider.
	 *
	 *     // Load the Twitter provider
	 *     $provider = $this->oauth2->provider('twitter');
	 *
	 * @param   string   provider name
	 * @param   array    provider options
	 * @return  OAuth_Provider
	 */
	public static function provider($name, array $options = NULL)
	{
		$name = ucfirst(strtolower($name));

		include_once 'Provider/'.$name.'.php';

		return new $name($options);
	}

}