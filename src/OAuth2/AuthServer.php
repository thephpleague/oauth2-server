<?php

namespace OAuth2;

class AuthServer
{
    protected $scopeDelimeter = ',';

    protected $expiresIn = 3600;

    protected $responseTypes = array(
        'code'
    );

    protected $storages = array();

    protected $grantTypes = array();

    protected $request = null;

    public function __construct($storage)
    {

    }

    public function addGrantType(GrantTypeInterface $grant_type, $identifier = null)
    {
        if (is_null($identifier)) {
            $identifier = $grant_type->getIdentifier();
        }
        $this->grantTypes[$identifier] = $grant_type;
    }

    public function getScopeDelimeter()
    {
        return $this->scopeDelimeter;
    }

    public function setScopeDelimeter($scope_delimeter)
    {
        $this->scopeDelimeter = $scope_delimeter;
    }

    public function getExpiresIn()
    {
        return $this->expiresIn;
    }

    public function setExpiresIn($expires_in)
    {
        $this->expiresIn = $expires_in;
    }

    /**
     * Sets the Request Object
     *
     * @param  RequestInterface The Request Object
     */
    public function setRequest(RequestInterface $request)
    {
        $this->request = $request;
    }

    /**
     * Gets the Request object.  It will create one from the globals if one is not set.
     *
     * @return  RequestInterface
     */
    public function getRequest()
    {
        if ($this->request === null) {
            $this->request = Request::buildFromGlobals();
        }

        return $this->request;
    }

    /**
     * Check client authorise parameters
     *
     * @access public
     * @param  array $authParams Optional array of parsed $_GET keys
     * @return array             Authorise request parameters
     */
    public function checkClientAuthoriseParams($authParams = null)
    {

    }

    /**
     * Parse a new authorise request
     *
     * @param  string $type            The session owner's type
     * @param  string $typeId          The session owner's ID
     * @param  array  $authoriseParams The authorise request $_GET parameters
     * @return string                  An authorisation code
     */
    public function newAuthoriseRequest($type, $typeId, $authoriseParams)
    {

    }

    /**
     * Issue an access token
     *
     * @access public
     * @param  array $authParams Optional array of parsed $_POST keys
     * @return array             Authorise request parameters
     */
    public function issueAccessToken($authParams = null)
    {

    }


    protected function getCurrentGrantType()
    {
        $grantType = $this->getRequest()->post('grant_type');

        if (is_null($grantType)) {
            throw new Exception
        }
    }

}
