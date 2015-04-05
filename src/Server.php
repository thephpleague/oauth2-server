<?php
namespace League\OAuth2\Server;

use DateInterval;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponseType;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Symfony\Component\HttpFoundation\Request;

class Server extends AbstractServer
{
    /**
     * @var \League\OAuth2\Server\Grant\GrantTypeInterface[]
     */
    protected $enabledGrantTypes = [];

    /**
     * @var \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface[]
     */
    protected $grantTypeResponseTypes = [];

    /**
     * @var DateInterval[]
     */
    protected $grantTypeAccessTokenTTL = [];

    /**
     * @var \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     */
    protected $defaultResponseType;

    /**
     * @var DateInterval
     */
    protected $defaultAccessTokenTTL;

    /**
     * @var string
     */
    protected $scopeDelimiter = ' ';

    /**
     * New server instance
     *
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $defaultResponseType
     * @param DateInterval                                              $defaultAccessTokenTTL
     */
    public function __construct(
        ResponseTypeInterface $defaultResponseType = null,
        DateInterval $defaultAccessTokenTTL = null
    ) {
        $this->defaultResponseType = ($defaultResponseType instanceof ResponseTypeInterface)
            ? $defaultResponseType
            : new BearerTokenResponseType();

        $this->defaultAccessTokenTTL = ($defaultAccessTokenTTL instanceof DateInterval)
            ? $defaultAccessTokenTTL
            : new DateInterval('PT01H'); // default of 1 hour

        parent::__construct();
    }

    /**
     * @param string                                                    $grantType
     * @param \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface $responseType
     * @param DateInterval                                              $accessTokenTTL
     *
     * @throws \Exception
     */
    public function enableGrantType(
        $grantType,
        ResponseTypeInterface $responseType = null,
        DateInterval $accessTokenTTL = null
    ) {
        if ($this->getContainer()->isInServiceProvider($grantType)) {
            $grant = $this->getContainer()->get($grantType);
            $grantIdentifier = $grant->getIdentifier();
            $this->enabledGrantTypes[$grantIdentifier] = $grant;
        } else {
            throw new \Exception('Unregistered grant type');
        }

        // Set grant response type
        if ($responseType instanceof ResponseTypeInterface) {
            $this->grantTypeResponseTypes[$grantIdentifier] = $responseType;
        } else {
            $this->grantTypeResponseTypes[$grantIdentifier] = $this->defaultResponseType;
        }

        // Set grant access token TTL
        if ($accessTokenTTL instanceof DateInterval) {
            $this->grantTypeAccessTokenTTL[$grantIdentifier] = $accessTokenTTL;
        } else {
            $this->grantTypeAccessTokenTTL[$grantIdentifier] = $this->defaultAccessTokenTTL;
        }
    }

    /**
     * Return an access token response
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \League\OAuth2\Server\ResponseTypes\ResponseTypeInterface
     * @throws \Exception
     */
    public function getAccessTokenResponse(Request $request = null)
    {
        if ($request === null) {
            $request = Request::createFromGlobals();
        }

        // Run the requested grant type
        $grantType = $request->request->get('grant_type', null);

        if ($grantType === null || !isset($this->enabledGrantTypes[$grantType])) {
            throw new \Exception('Unknown grant type');
        }

        $responseType = $this->enabledGrantTypes[$grantType]->getAccessTokenAsType(
            $request,
            $this->grantTypeResponseTypes[$grantType],
            $this->grantTypeAccessTokenTTL[$grantType],
            $this->scopeDelimiter
        );

        return $responseType->generateHttpResponse();
    }

    /**
     * Set the delimiter used to separate scopes in a request
     *
     * @param string $scopeDelimiter
     */
    public function setScopeDelimiter($scopeDelimiter)
    {
        $this->scopeDelimiter = $scopeDelimiter;
    }
}
