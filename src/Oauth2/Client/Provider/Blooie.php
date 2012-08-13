<?php

namespace Oauth2\Client\Provider;

class Blooie extends Oauth2\Client\Provider
{  
	public $scope = array('user.profile', 'user.picture');

	public $method = 'POST';

	public function url_authorize()
	{
		switch (ENVIRONMENT)
		{
			case PYRO_DEVELOPMENT:
				return 'http://local.bloo.ie/oauth';

			case PYRO_STAGING:
				return 'http://blooie-staging.pagodabox.com/oauth';

			case PYRO_PRODUCTIION:
				return 'https://bloo.ie/oauth';

			default:
				exit('What the crap?!');
		}
		
	}

	public function url_access_token()
	{
		switch (ENVIRONMENT)
		{
			case PYRO_DEVELOPMENT:
				return 'http://local.bloo.ie/oauth/access_token';

			case PYRO_STAGING:
				return 'http://blooie-staging.pagodabox.com/oauth/access_token';

			case PYRO_PRODUCTIION:
				return 'https://bloo.ie/oauth/access_token';

			default:
		}

	public function get_user_info(OAuth2_Token_Access $token)
	{
		$url = 'https://graph.facebook.com/me?'.http_build_query(array(
			'access_token' => $token->access_token,
		));

		$user = json_decode(file_get_contents($url));

		// Create a response from the request
		return array(
			'uid' => $user->id,
			'nickname' => $user->username,
			'name' => $user->name,
			'first_name' => $user->first_name,
			'last_name' => $user->last_name,
			'email' => isset($user->email) ? $user->email : null,
			'location' => isset($user->hometown->name) ? $user->hometown->name : null,
			'description' => isset($user->bio) ? $user->bio : null,
			'image' => 'https://graph.facebook.com/me/picture?type=normal&access_token='.$token->access_token,
			'urls' => array(
			  'Facebook' => $user->link,
			),
		);
	}
}
