<?php

namespace Oauth2\Client;

/**
 * OAuth2 Provider
 *
 * @package    CodeIgniter/OAuth2
 * @category   Provider
 * @author     Phil Sturgeon
 * @copyright  (c) 2012 HappyNinjas Ltd
 * @license    http://philsturgeon.co.uk/code/dbad-license
 */

abstract class IDP
{
	/**
	 * @var  string  provider name
	 */
	public $name;

	/**
	 * @var  string  uid key name
	 */
	public $uidKey = 'uid';

	/**
	 * @var  string  additional request parameters to be used for remote requests
	 */
	public $callback;

	/**
	 * @var  array  additional request parameters to be used for remote requests
	 */
	protected $params = array();

	/**
	 * @var  string  the method to use when requesting tokens
	 */
	protected $method = 'GET';

	/**
	 * @var  string  default scope (useful if a scope is required for user info)
	 */
	protected $scope;

	/**
	 * @var  string  scope separator, most use "," but some like Google are spaces
	 */
	protected $scopeSeperator = ',';

	/**
	 * Overloads default class properties from the options.
	 *
	 * Any of the provider options can be set here, such as app_id or secret.
	 *
	 * @param   array   provider options
	 * @return  void
	 */
	public function __construct(array $options = array())
	{
		if ( ! $this->name)
		{
			// Attempt to guess the name from the class name
			$this->name = strtolower(substr(get_class($this), strlen('OAuth2_Provider_')));
		}

		if (empty($options['id']))
		{
			throw new Exception('Required option not provided: id');
		}

		$this->clientId = $options['id'];
		
		isset($options['callback']) and $this->callback = $options['callback'];
		isset($options['secret']) and $this->client_secret = $options['secret'];
		isset($options['scope']) and $this->scope = $options['scope'];

		$this->redirectUri = site_url(get_instance()->uri->uri_string());
	}

	/**
	 * Return the value of any protected class variable.
	 *
	 *     // Get the provider signature
	 *     $signature = $provider->signature;
	 *
	 * @param   string  variable name
	 * @return  mixed
	 */
	public function __get($key)
	{
		return $this->$key;
	}

	/**
	 * Returns the authorization URL for the provider.
	 *
	 *     $url = $provider->url_authorize();
	 *
	 * @return  string
	 */
	abstract public function url_authorize();

	/**
	 * Returns the access token endpoint for the provider.
	 *
	 *     $url = $provider->url_access_token();
	 *
	 * @return  string
	 */
	abstract public function url_access_token();

	/*
	* Get an authorization code from Facebook.  Redirects to Facebook, which this redirects back to the app using the redirect address you've set.
	*/	
	public function authorize($options = array())
	{
		$state = md5(uniqid(rand(), TRUE));
		get_instance()->session->set_userdata('state', $state);

		$params = array(
			'client_id' 		=> $this->client_id,
			'redirect_uri' 		=> isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->redirect_uri,
			'state' 			=> $state,
			'scope'				=> is_array($this->scope) ? implode($this->scopeSeperator, $this->scope) : $this->scope,
			'response_type' 	=> 'code',
			'approval_prompt'   => 'force' // - google force-recheck
		);
		
		redirect($this->url_authorize().'?'.http_build_query($params));
	}

	/*
	* Get access to the API
	*
	* @param	string	The access code
	* @return	object	Success or failure along with the response details
	*/	
	public function access($code, $options = array())
	{
		$params = array(
			'client_id' 	=> $this->clientId,
			'client_secret' => $this->clientSecret,
			'grant_type' 	=> isset($options['grant_type']) ? $options['grant_type'] : 'authorization_code',
		);

		switch ($params['grant_type'])
		{
			case 'authorization_code':
				$params['code'] = $code;
				$params['redirect_uri'] = isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->redirect_uri;
			break;

			case 'refresh_token':
				$params['refresh_token'] = $code;
			break;
		}

		$response = null;	
		$url = $this->url_access_token();

		switch ($this->method)
		{
			case 'GET':

				// Need to switch to Request library, but need to test it on one that works
				$url .= '?'.http_build_query($params);
				$response = file_get_contents($url);

				parse_str($response, $return);

			break;

			case 'POST':

				/* 	$ci = get_instance();

				$ci->load->spark('curl/1.2.1');

				$ci->curl
					->create($url)
					->post($params, array('failonerror' => false));

				$response = $ci->curl->execute();
				*/

				$opts = array(
					'http' => array(
						'method'  => 'POST',
						'header'  => 'Content-type: application/x-www-form-urlencoded',
						'content' => http_build_query($params),
					)
				);

				$defaultOpts = stream_context_get_params(stream_context_get_default());
				$context = stream_context_create(array_merge_recursive($defaultOpts['options'], $opts));
				$response = file_get_contents($url, false, $context);

				$return = json_decode($response, true);

			break;

			default:
				throw new OutOfBoundsException("Method '{$this->method}' must be either GET or POST");
		}

		if ( ! empty($return['error']))
		{
			throw new OAuth2_Exception($return);
		}
		
		switch ($params['grant_type'])
		{
			case 'authorization_code':
				return OAuth2_Token::factory('access', $return);
			break;

			case 'refresh_token':
				return OAuth2_Token::factory('refresh', $return);
			break;
		}
		
	}

}
