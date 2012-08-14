<?php

namespace Oauth2\Resource;

class OAuthResourceServerException extends \Exception
{

}

class Server
{
    /**
     * The access token.
     * @access private
     */
    private $_accessToken = NULL;

    /**
     * The scopes the access token has access to.
     * @access private
     */
    private $_scopes = array();

    /**
     * The type of owner of the access token.
     * @access private
     */
    private $_type = NULL;

    /**
     * The ID of the owner of the access token.
     * @access private
     */
    private $_typeId = NULL;

    /**
     * Server configuration
     * @var array
     */
    private $config = array(
        'token_key' =>  'oauth_token'
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
     * @param  [type] $method     [description]
     * @param  [type] $arguements [description]
     * @return [type]             [description]
     */
    public function __call($method, $arguements)
    {
        if (substr($method, 0, 2) === 'is')
        {
            if ($this->_type === strtolower(substr($method, 2)))
            {
                return $this->_typeId;
            }
            
            return false;
        }
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
        $this->db = $db;
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
        switch ($server['REQUEST_METHOD'])
        {           
            case 'POST':
                $accessToken = isset($_POST[$this->config['token_key']]) ? $_POST[$this->config['token_key']] : null;
                break;

            default:
            $accessToken = isset($_GET[$this->config['token_key']]) ? $_GET[$this->config['token_key']] : null;
                break;
        }

        // Try and get an access token from the auth header
        $headers = getallheaders();
        if (isset($headers['Authorization']))
        {
            $rawToken = trim(str_replace('Bearer', '', $headers['Authorization']));
            if ( ! empty($rawToken))
            {
                $accessToken = base64_decode($rawToken);
            }
        }
        
        if ($accessToken)
        {
            $sessionQuery = $this->ci->db->get_where('oauth_sessions', array('access_token' => $accessToken, 'stage' => 'granted'));
            
            if ($session_query->num_rows() === 1)
            {
                $session = $session_query->row();
                $this->_accessToken = $session->access_token;
                $this->_type = $session->type;
                $this->_typeId = $session->type_id;
                
                $scopes_query = $this->ci->db->get_where('oauth_session_scopes', array('access_token' => $accessToken));
                if ($scopes_query->num_rows() > 0)
                {
                    foreach ($scopes_query->result() as $scope)
                    {
                        $this->_scopes[] = $scope->scope;
                    }
                }
            }
            
            else
            {
                $this->ci->output->set_status_header(403);
                $this->ci->output->set_output('Invalid access token');
            }
        }
        
        else
        {
            $this->ci->output->set_status_header(403);
            $this->ci->output->set_output('Missing access token');
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
        if (is_string($scopes))
        {
            if (in_array($scopes, $this->_scopes))
            {
                return true;
            }
            
            return false;
        }
        
        elseif (is_array($scopes))
        {
            foreach ($scopes as $scope)
            {
                if ( ! in_array($scope, $this->_scopes))
                {
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
    private function dbcall()
    {
        if ($this->db === null) {
            throw new OAuthResourceServerException('No registered database abstractor');
        }

        if ( ! $this->db instanceof Database) {
            throw new OAuthResourceServerException('Registered database abstractor is not an instance of Oauth2\Resource\Database');
        }

        $args = func_get_args();
        $method = $args[0];
        unset($args[0]);
        $params = array_values($args);

        return call_user_func_array(array($this->db, $method), $args);
    }
}