<?php
/**
 * Foursquare OAuth2 Provider
 *
 * @package    CodeIgniter/OAuth2
 * @category   Provider
 * @author     Phil Sturgeon
 * @copyright  (c) 2012 HappyNinjas Ltd
 * @license    http://philsturgeon.co.uk/code/dbad-license
 */

class OAuth2_Provider_Foursquare extends OAuth2_Provider
{  
	public $method = 'POST';

	public function url_authorize()
	{
		return 'https://foursquare.com/oauth2/authenticate';
	}

	public function url_access_token()
	{
		return 'https://foursquare.com/oauth2/access_token';
	}

	public function get_user_info(OAuth2_Token_Access $token)
	{
		$url = 'https://api.foursquare.com/v2/users/self?'.http_build_query(array(
			'oauth_token' => $token->access_token,
		));

		$response = json_decode(file_get_contents($url));

		$user = $response->response->user;

		// Create a response from the request
		return array(
			'uid' => $user->id,
			//'nickname' => $user->login,
			'name' => sprintf('%s %s', $user->firstName, $user->lastName),
			'email' => $user->contact->email,
			'image' => $user->photo,
			'location' => $user->homeCity,
		);
	}
}