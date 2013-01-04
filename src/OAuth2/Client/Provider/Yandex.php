<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Yandex OAuth2 Provider
 *
 * @package    CodeIgniter/OAuth2
 * @category   Provider
 * @author     Lavr Lyndin
 */

class OAuth2_Provider_Yandex extends OAuth2_Provider
{
	public $method = 'POST';
	
	public function url_authorize()
	{
		return 'https://oauth.yandex.ru/authorize';
	}

	public function url_access_token()
	{
		return 'https://oauth.yandex.ru/token';
	}

	public function get_user_info(OAuth2_Token_Access $token)
	{
		$opts = array(
			'http' => array(
				'method' => 'GET',
				'header' => 'Authorization: OAuth '.$token->access_token
			)
		);
		$_default_opts = stream_context_get_params(stream_context_get_default());
		
		$opts = array_merge_recursive($_default_opts['options'], $opts);
		$context = stream_context_create($opts);
		$url = 'http://api-yaru.yandex.ru/me/?format=json';

		$user = json_decode(file_get_contents($url,false,$context));

		preg_match("/\d+$/",$user->id,$uid);
		
		return array(
			'uid' => $uid[0],
			'nickname' => isset($user->name) ? $user->name : null,
			'name' => isset($user->name) ? $user->name : null,
			'first_name' => isset($user->first_name) ? $user->first_name : null,
			'last_name' => isset($user->last_name) ? $user->last_name : null,
			'email' => isset($user->email) ? $user->email : null,
			'location' => isset($user->hometown->name) ? $user->hometown->name : null,
			'description' => isset($user->bio) ? $user->bio : null,
			'image' => $user->links->userpic,
		);
	}
	
	public function access($code, $options = array())
	{
		$params = array(
			'client_id' 	=> $this->client_id,
			'client_secret' => $this->client_secret,
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

		$curl = curl_init($url);

		$headers[] = 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8;';
		curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

//		curl_setopt($curl, CURLOPT_USERAGENT, 'yamolib-php');
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($curl, CURLOPT_TIMEOUT, 80);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		//        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
		//        curl_setopt($curl, CURLOPT_CAINFO, dirname(__FILE__) . '/../data/ca-certificate.crt');

		$response = curl_exec($curl);
		curl_close($curl);

		$return = json_decode($response, true);

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
