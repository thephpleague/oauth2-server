<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\StorageInterface;
use League\OAuth2\Server\AbstractServer;

class BaseStorage implements StorageInterface
{
	protected $documentManager;
	
	public function __construct($documentManager){
		$this->documentManager = $documentManager;
	}
	
	protected $server;
	
	/**
	 * Set the server
	 */
	public function setServer(AbstractServer $server){
		$this->server = $server;
	}
}