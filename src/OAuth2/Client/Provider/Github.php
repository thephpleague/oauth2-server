<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * GitHub OAuth2 Provider
 *
 * @package    CodeIgniter/OAuth2
 * @category   Provider
 * @author     Phil Sturgeon
 * @copyright  (c) 2012 HappyNinjas Ltd
 * @license    http://philsturgeon.co.uk/code/dbad-license
 */

class OAuth2_Provider_Github extends OAuth2\Client\IDP
{
	public function urlAuthorize()
	{
		return 'https://github.com/login/oauth/authorize';
	}

	public function urlAccessToken()
	{
		return 'https://github.com/login/oauth/access_token';
	}

	public function getUserInfo(Oauth\Token\Access $token)
	{
		$url = 'https://api.github.com/user?'.http_build_query(array(
			'access_token' => $token->access_token,
		));

		$user = json_decode(file_get_contents($url));

		return array(
			'uid' => $user->id,
			'nickname' => $user->login,
			'name' => $user->name,
			'email' => $user->email,
			'urls' => array(
			  'GitHub' => 'http://github.com/'.$user->login,
			  'Blog' => $user->blog,
			),
		);
	}
}