<?php
/**
 * OAuth2 Token
 *
 * @package    OAuth2
 * @category   Token
 * @author     Phil Sturgeon
 * @copyright  (c) 2011 HappyNinjas Ltd
 */

class Authorize extends \OAuth2\Client\Token
{
	/**
	 * @var  string  code
	 */
	protected $code;

	/**
	 * @var  string  redirect_uri
	 */
	protected $redirectUri;

	/**
	 * Sets the token, expiry, etc values.
	 *
	 * @param   array   token options
	 * @return  void
	 */
	public function __construct(array $options)
	{
		if ( ! isset($options['code'])) {

            throw new Exception('Required option not passed: code');

        } elseif ( ! isset($options['redirect_uri'])) {

            throw new Exception('Required option not passed: redirect_uri');

        }

		$this->code = $options['code'];
		$this->redirectUri = $options['redirect_uri'];
	}

	/**
	 * Returns the token key.
	 *
	 * @return  string
	 */
	public function __toString()
	{
		return (string) $this->code;
	}

}