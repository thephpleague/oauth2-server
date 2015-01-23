<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\MacTokenInterface;
use MongoDBExample\Document\OAuthMacToken;

class MacTokenStorage extends BaseStorage implements MacTokenInterface
{

    public function create($macKey, $accessToken){
        $macToken = new OAuthMacToken();
        $macToken->id = $macKey;
        $macToken->setAccessToken($this->documentManager->getRepository("MongoDBExample\Document\OAuthAccessToken")->find($accessToken));

        $this->documentManager->persist($macToken);
        $this->documentManager->flush();
    }

    public function getByAccessToken($accessToken){
        if($macToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthMacToken")->findOneBy(array("AccessToken" => $accessToken)))
            return $macToken;
        else
            return;
    }
}