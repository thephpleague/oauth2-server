<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\RuntimeException;

/**
 * Abstract grant type
 */
abstract class AbstractGrantType implements GrantTypeInterface
{
    /**
     * Constants of the grant type that must be redefined in child classes
     */
    const GRANT_IDENTIFIER    = null;
    const GRANT_RESPONSE_TYPE = null;

    /**
     * The Authorization server used to perform various tasks on the grant type
     *
     * @var AuthorizationServer
     */
    protected $authorizationServer;

    /**
     * Access token TTL (used to override the default value of the authorization server)
     *
     * @var int|null
     */
    protected $accessTokenTTL;

    /**
     * Constructor
     *
     * @param AuthorizationServer $authorizationServer
     */
    public function __construct(AuthorizationServer $authorizationServer)
    {
        $this->authorizationServer = $authorizationServer;
    }

    /**
     * Return the grant type identifier
     *
     * @return string
     * @throws RuntimeException If no grant identifier is set
     */
    public function getIdentifier()
    {
        if (null === static::GRANT_IDENTIFIER) {
            throw new RuntimeException(sprintf(
                'The grant type "%s" does not have any identifier',
                get_called_class()
            ));
        }

        return static::GRANT_IDENTIFIER;
    }

    /**
     * Return the grant type response type
     *
     * @return string
     * @throws RuntimeException
     */
    public function getResponseType()
    {
        if (null === static::GRANT_RESPONSE_TYPE) {
            throw new RuntimeException(sprintf(
                'The grant type "%s" does not have any response type',
                get_called_class()
            ));
        }

        return static::GRANT_RESPONSE_TYPE;
    }

    /**
     * Override the default authorization server access token expire time
     *
     * @param  int $accessTokenTTL
     * @return void
     */
    public function setAccessTokenTTL($accessTokenTTL)
    {
        $this->accessTokenTTL = (int) $accessTokenTTL;
    }

    /**
     * Validate a scope against the authorization server
     *
     * @param  array|string $scopes
     * @return array
     * @throws ClientException
     */
    public function validateScopes($scopes = [])
    {
        $scopesList = explode($this->authorizationServer->getScopeDelimiter(), $scopes);

        for ($i = 0; $i < count($scopesList); $i++) {
            $scopesList[$i] = trim($scopesList[$i]);
            if ($scopesList[$i] === '') unset($scopesList[$i]); // Remove any junk scopes
        }

        if (
            $this->server->scopeParamRequired() === true &&
            $this->server->getDefaultScope() === null &&
            count($scopesList) === 0
        ) {
            throw new ClientException(sprintf($this->server->getExceptionMessage('invalid_request'), 'scope'), 0);
        } elseif (count($scopesList) === 0 && $this->server->getDefaultScope() !== null) {
            if (is_array($this->server->getDefaultScope())) {
                $scopesList = $this->server->getDefaultScope();
            } else {
                $scopesList = [0 => $this->server->getDefaultScope()];
            }
        }

        $scopes = [];

        foreach ($scopesList as $scopeItem) {
            $scopeDetails = $this->server->getStorage('scope')->getScope(
                $scopeItem,
                $client->getId(),
                $this->getIdentifier()
            );

            if ($scopeDetails === false) {
                throw new ClientException(sprintf($this->server->getExceptionMessage('invalid_scope'), $scopeItem), 4);
            }

            $scope = new Scope($this->server->getStorage('scope'));
            $scope->setId($scopeDetails['id']);
            $scope->setName($scopeDetails['name']);

            $scopes[] = $scope;
        }

        return $scopes;
    }
}
