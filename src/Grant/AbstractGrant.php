<?php
/**
 * OAuth 2.0 Abstract grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\Event\Emitter;
use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntity;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

/**
 * Abstract grant class
 */
abstract class AbstractGrant implements GrantTypeInterface
{
    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = '';

    /**
     * Grant responds with
     *
     * @var string
     */
    protected $respondsWith = 'token';

    /**
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * @var ClientRepositoryInterface
     */
    protected $clientRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @var \League\Event\Emitter
     */
    protected $emitter;

    /**
     * @var ScopeRepositoryInterface
     */
    protected $scopeRepository;

    /**
     * @param \League\Event\Emitter                                             $emitter
     * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface      $clientRepository
     * @param \League\OAuth2\Server\Repositories\ScopeRepositoryInterface       $scopeRepository
     * @param \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(
        Emitter $emitter,
        ClientRepositoryInterface $clientRepository,
        ScopeRepositoryInterface $scopeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository
    ) {
        $this->emitter = $emitter;
        $this->clientRepository = $clientRepository;
        $this->scopeRepository = $scopeRepository;
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * {@inheritdoc}
     */
    public function respondsWith()
    {
        return $this->respondsWith;
    }

    /**
     * @param string                $scopeParamValue A string containing a delimited set of scope identifiers
     * @param string                $scopeDelimiter  The delimiter between the scopes in the value string
     * @param ClientEntityInterface $client
     * @param string                $redirectUri
     *
     * @return \League\OAuth2\Server\Entities\ScopeEntity[]
     * @throws \League\OAuth2\Server\Exception\InvalidScopeException
     */
    public function validateScopes(
        $scopeParamValue,
        $scopeDelimiter,
        ClientEntityInterface $client,
        $redirectUri = null
    ) {
        $scopesList = explode($scopeDelimiter, trim($scopeParamValue));

        for ($i = 0; $i < count($scopesList); $i++) {
            $scopesList[$i] = trim($scopesList[$i]);
            if ($scopesList[$i] === '') {
                unset($scopesList[$i]); // Remove any junk scopes
            }
        }

        $scopes = [];
        foreach ($scopesList as $scopeItem) {
            $scope = $this->scopeRepository->get(
                $scopeItem,
                $this->getIdentifier(),
                $client->getIdentifier()
            );

            if (($scope instanceof ScopeEntity) === false) {
                throw new Exception\InvalidScopeException($scopeItem, $redirectUri);
            }

            $scopes[] = $scope;
        }

        return $scopes;
    }
}
