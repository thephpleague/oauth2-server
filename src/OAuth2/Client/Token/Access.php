<?php

namespace OAuth2\Client\Token;

/**
 * OAuth2 Token
 *
 * @package    OAuth2
 * @category   Token
 * @author     Phil Sturgeon
 * @copyright  (c) 2011 HappyNinjas Ltd
 */

class Access extends \OAuth2\Client\Token
{
	/**
	 * @var  string  accessToken
	 */
	protected $accessToken;

	/**
	 * @var  int  expires
	 */
	protected $expires;

	/**
	 * @var  string  refreshToken
	 */
	protected $refreshToken;

	/**
	 * @var  string  uid
	 */
	protected $uid;

	/**
	 * Sets the token, expiry, etc values.
	 *
	 * @param   array   token options
	 * @return  void
	 */
	public function __construct(array $options = null)
	{
		if ( ! isset($options['access_token'])) {
			throw new \BadMethodCallException('Required option not passed: access_token'.PHP_EOL.print_r($options, true));
		}

		$this->accessToken = $options['access_token'];

		// Some providers (not many) give the uid here, so lets take it
		isset($options['uid']) and $this->uid = $options['uid'];

		//Vkontakte uses user_id instead of uid
		isset($options['user_id']) and $this->uid = $options['user_id'];

		//Mailru uses x_mailru_vid instead of uid
		isset($options['x_mailru_vid']) and $this->uid = $options['x_mailru_vid'];

		// We need to know when the token expires, add num. seconds to current time
		isset($options['expires_in']) and $this->expires = time() + ((int) $options['expires_in']);

		// Facebook is just being a spec ignoring jerk
		isset($options['expires']) and $this->expires = time() + ((int) $options['expires']);

		// Grab a refresh token so we can update access tokens when they expires
		isset($options['refresh_token']) and $this->refreshToken = $options['refresh_token'];
	}

	/**
	 * Returns the token key.
	 *
	 * @return  string
	 */
	public function __toString()
	{
		return (string) $this->accessToken;
	}

}