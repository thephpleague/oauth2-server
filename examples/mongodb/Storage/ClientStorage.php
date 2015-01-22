<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;

class ClientStorage extends BaseStorage implements ClientInterface
{
	/**
	 * Validate a client
	 */
	public function get($clientId, $clientSecret = null, $redirectUri = null, $grantType = null){
		$filter = array(
			"_id" => $clientId
		);
		
		if ($clientSecret !== null)
			$filter['Secret'] = md5($clientSecret);
		
		if ($redirectUri)
			$filter['RedirectURI'] = $redirectUri;
		
		
		$Client = $this->documentManager->getRepository("MongoDBExample\Document\OAuthClient")->findOneBy($filter);
		if($Client)
			return $Client;
		else
			return;
	}
	
	/**
	 * Get the client associated with a session
	*/
	public function getBySession(SessionEntityInterface $session){
		return $session->getClient();
	}
}