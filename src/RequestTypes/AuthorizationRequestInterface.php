<?php
/**
 * @author      Patrick Rodacker <dev@rodacker.de>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\RequestTypes;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;

interface AuthorizationRequestInterface
{
    /**
     * @return UserEntityInterface|null
     */
    public function getUser();

    /**
     * @param string $state
     */
    public function setState($state);

    /**
     * @return ClientEntityInterface
     */
    public function getClient();

    /**
     * @param bool $authorizationApproved
     */
    public function setAuthorizationApproved($authorizationApproved);

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function setScopes(array $scopes);

    /**
     * @param string|null $redirectUri
     */
    public function setRedirectUri($redirectUri);

    /**
     * @return string|null
     */
    public function getRedirectUri();

    /**
     * @return string
     */
    public function getCodeChallengeMethod();

    /**
     * @param string $grantTypeId
     */
    public function setGrantTypeId($grantTypeId);

    /**
     * @param UserEntityInterface $user
     */
    public function setUser(UserEntityInterface $user);

    /**
     * @param ClientEntityInterface $client
     */
    public function setClient(ClientEntityInterface $client);

    /**
     * @param string $codeChallenge
     */
    public function setCodeChallenge($codeChallenge);

    /**
     * @return bool
     */
    public function isAuthorizationApproved();

    /**
     * @return string|null
     */
    public function getState();

    /**
     * @return string
     */
    public function getCodeChallenge();

    /**
     * @param string $codeChallengeMethod
     */
    public function setCodeChallengeMethod($codeChallengeMethod);

    /**
     * @return ScopeEntityInterface[]
     */
    public function getScopes();

    /**
     * @return string
     */
    public function getGrantTypeId();
}
