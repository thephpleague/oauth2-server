<?php

namespace Oauth2\Resource;

class ServerException extends \Exception
{

}

class ClientException extends \Exception
{

}

class Server
{
    /**
     * Reference to the database abstractor
     * @var object
     */
    private $_db = null;

    /**
     * The access token.
     * @access private
     */
    private $_accessToken = null;

    /**
     * The scopes the access token has access to.
     * @access private
     */
    private $_scopes = array();

    /**
     * The type of owner of the access token.
     * @access private
     */
    private $_type = null;

    /**
     * The ID of the owner of the access token.
     * @access private
     */
    private $_typeId = null;

    /**
     * Server configuration
     * @var array
     */
    private $_config = array(
        'token_key' =>  'oauth_token'
    );

    /**
     * Error codes.
     * 
     * To provide i8ln errors just overwrite the keys
     * 
     * @var array
     */
    public $errors = array(
        'missing_access_token'  =>  'An access token was not presented with the request',
        'invalid_access_token'  =>  'The access token is not registered with the resource server',
        'missing_access_token_details'  =>  'The registered database abstractor did not return a valid access token details response',
        'invalid_access_token_scopes'   =>  'The registered database abstractor did not return a valid access token scopes response',
    );

    /**
     * Constructor
     * 
     * @access public
     * @return void
     */
    public function __construct($options = null)
    {
        if ($options !== null) {
            $this->config = array_merge($this->config, $options);
        }
    }

    /**
     * Magic method to test if access token represents a particular owner type
     * @param  string $method     The method name
     * @param  mixed  $arguements The method arguements
     * @return bool               If method is valid, and access token is owned by the requested party then true,
     */
    public function __call($method, $arguements = null)
    {
        if (substr($method, 0, 2) === 'is') {

            if ($this->_type === strtolower(substr($method, 2))) {
                return $this->_typeId;
            }
            
            return false;
        }

        trigger_error('Call to undefined function ' . $method . '()');
    }

    /**
     * Register a database abstrator class
     * 
     * @access public
     * @param  object $db A class that implements OAuth2ServerDatabase
     * @return void
     */
    public function registerDbAbstractor($db)
    {
        $this->_db = $db;
    }
    
    /**
     * Init function
     * 
     * @access public
     * @return void
     */
    public function init()
    {
        $accessToken = null;

        // Try and get the access token via an access_token or oauth_token parameter
        switch ($_SERVER['REQUEST_METHOD'])
        {           
            case 'POST':
                $accessToken = isset($_POST[$this->_config['token_key']]) ? $_POST[$this->_config['token_key']] : null;
                break;

            default:
            $accessToken = isset($_GET[$this->_config['token_key']]) ? $_GET[$this->_config['token_key']] : null;
                break;
        }

        // Try and get an access token from the auth header
        if (function_exists('getallheaders')) {

            $headers = getallheaders();
            
            if (isset($headers['Authorization'])) {

                $rawToken = trim(str_replace('Bearer', '', $headers['Authorization']));

                if ( ! empty($rawToken)) {
                    $accessToken = base64_decode($rawToken);
                }
            }
        }
        
        if ($accessToken) {

            $result = $this->_dbCall('validateAccessToken', $accessToken);

            if ($result === false) {

                throw new ClientException($this->errors['invalid_access_token']);

            } else {

                if ( ! array_key_exists('id', $result) || ! array_key_exists('owner_id', $result) || 
                     ! array_key_exists('owner_type', $result)) {
                    throw new ServerException($this->errors['missing_access_token_details']);
                }

                $this->_accessToken = $accessToken;
                $this->_type = $result['owner_type'];
                $this->_typeId = $result['owner_id'];

                // Get the scopes
                $scopes = $this->_dbCall('sessionScopes', $result['id']);

                if ( ! is_array($scopes))
                {
                    throw new ServerException($this->errors['invalid_access_token_scopes']);
                }

                $this->_scopes = $scopes;
            }

        } else {

            throw new ClientException($this->errors['missing_access_token']);

        }
    }
    
    /**
     * Test if the access token has a specific scope
     * 
     * @param mixed $scopes Scope(s) to check
     * 
     * @access public
     * @return string|bool
     */
    public function hasScope($scopes)
    {
        if (is_string($scopes)) {

            if (in_array($scopes, $this->_scopes)) {
                return true;
            }
            
            return false;

        } elseif (is_array($scopes)) {

            foreach ($scopes as $scope) {

                if ( ! in_array($scope, $this->_scopes)) {
                    return false;
                }

            }
            
            return true;
        }
        
        return false;
    }

    /**
     * Call database methods from the abstractor
     * 
     * @return mixed The query result
     */
    private function _dbCall()
    {
        if ($this->_db === null) {
            throw new ServerException('No registered database abstractor');
        }

        if ( ! $this->_db instanceof Database) {
            throw new ServerException('The registered database abstractor is not an instance of Oauth2\Resource\Database');
        }

        $args = func_get_args();
        $method = $args[0];
        unset($args[0]);
        $params = array_values($args);

        return call_user_func_array(array($this->_db, $method), $params);
    }
}