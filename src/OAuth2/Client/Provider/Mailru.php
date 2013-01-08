<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Mailru OAuth2 Provider
 *
 * @package    CodeIgniter/OAuth2
 * @category   Provider
 * @author     Lavr Lyndin
 */

class OAuth2_Provider_Mailru extends OAuth2_Provider
{
	public $method = 'POST';

	public function url_authorize()
	{
		return 'https://connect.mail.ru/oauth/authorize';
	}

	public function url_access_token()
	{
		return 'https://connect.mail.ru/oauth/token';
	}
	
	protected function sign_server_server(array $request_params, $secret_key)
	{
		ksort($request_params);
		$params = '';
		foreach ($request_params as $key => $value) {
			$params .= "$key=$value";
		}
		return md5($params . $secret_key);
	}

	public function get_user_info(OAuth2_Token_Access $token)
	{
		$request_params = array(
			'app_id' => $this->client_id,
			'method' => 'users.getInfo',
			'uids' => $token->uid,
			'access_token' => $token->access_token,
			'secure' => 1
		);
		
		$sig = $this->sign_server_server($request_params,$this->client_secret);
		$url = 'http://www.appsmail.ru/platform/api?'.http_build_query($request_params).'&sig='.$sig;

		$user = json_decode(file_get_contents($url));

		return array(
			'uid' => $user[0]->uid,
			'nickname' => $user[0]->nick,
			'name' => $user[0]->first_name.' '.$user[0]->last_name,
			'first_name' => $user[0]->first_name,
			'last_name' => $user[0]->last_name,
			'email' => isset($user[0]->email) ? $user[0]->email : null,
			'image' => isset($user[0]->pic_big) ? $user[0]->pic_big : null,
		);
	}
	
	public function authorize($options = array())
	{
		$state = md5(uniqid(rand(), TRUE));
		get_instance()->session->set_userdata('state', $state);

		$params = array(
			'client_id' 		=> $this->client_id,
			'redirect_uri' 		=> isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->redirect_uri,
			'response_type' 	=> 'code',
		);

		redirect($this->url_authorize().'?'.http_build_query($params));
	}
}
