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

class Foursquare extends OAuth2\Client\IDP
{
	public $method = 'POST';

	public function urlAuthorize()
	{
		return 'https://foursquare.com/oauth2/authenticate';
	}

	public function urlAccessToken()
	{
		return 'https://foursquare.com/oauth2/access_token';
	}

	public function getUserInfo(OAuth2\Token\Access $token)
	{
		$url = 'https://api.foursquare.com/v2/users/self?'.http_build_query(array(
			'oauth_token' => $token->access_token,
		));

		$response = json_decode(file_get_contents($url));

		$user = $response->response->user;

		// Create a response from the request
		return array(
			'uid' => $user->id,
			'name' => sprintf('%s %s', $user->firstName, $user->lastName),
			'email' => $user->contact->email,
			'image' => $user->photo,
			'location' => $user->homeCity,
		);
	}
}