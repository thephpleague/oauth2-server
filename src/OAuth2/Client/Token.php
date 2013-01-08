<?php

namespace OAuth2\Client;

abstract class Token
{

	/**
	 * Create a new token object.
	 *
	 * @param   string  token type
	 * @param   array   token options
	 * @return  Token
	 */
	public static function factory($name = 'access', array $options = null)
	{
		include_once 'Token/'.ucfirst(strtolower($name)).'.php';

		$class = 'OAuth2\Client\Token\\'.ucfirst($name);

		return new $class($options);
	}

	/**
	 * Return the value of any protected class variable.
	 *
	 * @param   string  variable name
	 * @return  mixed
	 */
	public function __get($key)
	{
		return $this->$key;
	}

	/**
	 * Return a boolean if the property is set
	 *
	 * @param   string  variable name
	 * @return  bool
	 */
	public function __isset($key)
	{
		return isset($this->$key);
	}

} // End Token
