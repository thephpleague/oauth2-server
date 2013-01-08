<?php

namespace OAuth2\Client;

class Provider
{
	private function __constuct() {}

	public static function factory($name, array $options = null)
	{
		if ( ! class_exists($name)) {

			throw new OAuth2\Client\Exception('There is no identity provider called: '.$name);

		}

		return new $name($options);
	}
}