<?php

class Blooie extends OAuth2\Client\IDP
{
	public $scope = array('user.profile', 'user.picture');

	public $method = 'POST';

	public function urlAuthorize()
	{
		return 'https://bloo.ie/oauth';
	}

	public function urlAccessToken()
	{
		return 'https://bloo.ie/oauth/access_token';
	}

	public function getUserInfo(OAuth2\Token\Access $token)
	{
		$url = 'https://graph.facebook.com/me?'.http_build_query(array(
			'access_token' => $token->access_token,
		));

		$user = json_decode(file_get_contents($url));

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
