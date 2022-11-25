<?php

namespace League\OAuth2\Server\ResponseTypes;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\ClaimExtractor;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\IdTokenClaimsCreated;
use League\OAuth2\Server\IdTokenIssued;
use League\OAuth2\Server\Repositories\ClaimSetRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;

/**
 * OpenidConfigurationResponse
 *
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenResponse extends BearerTokenResponse
{
    use EmitterAwareTrait;

    public function __construct(
        protected ServerRequestInterface $request,
        protected ClaimSetRepositoryInterface $claimRepository,
        protected ?ClaimExtractor $extractor = null
    )
    {
        if (!$extractor) {
            $this->extractor = new ClaimExtractor();
        }
    }

    /**
     * @param AccessTokenEntityInterface $accessToken
     *
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        // Onyly add id_token to openid scopes
        if (!self::isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        $claimSet = $this->claimRepository->getClaimSetEntry($accessToken);

        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy(\sprintf(
                '%s://%s',
                $this->request->getUri()->getScheme(),
                $this->request->getUri()->getHost()
            ))
            ->issuedAt(new \DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($accessToken->getUserIdentifier());

        if ($claimSet instanceof ClaimSetInterface) {
            foreach ($this->extractor->extract($accessToken->getScopes(), $claimSet->getClaims()) as $claimName => $claimValue) {
                $builder->withClaim($claimName, $claimValue);
            }
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
        if (\array_key_exists($nonce = 'nonce', $this->request->getParsedBody())) {
            $builder->withClaim($nonce, $this->request->getParsedBody()[$nonce]);
        }

        $this->getEmitter()->emit(
            new IdTokenClaimsCreated(RequestEvent::ID_TOKEN_CLAIMS_CREATED, $this->request, $builder)
        );

        $token = $builder->getToken(
            new Sha256(),
            InMemory::file($this->privateKey->getKeyPath(), (string) $this->privateKey->getPassPhrase())
        );

        $this->getEmitter()->emit(
            new IdTokenIssued(RequestEvent::ID_TOKEN_ISSUED, $this->request, $token)
        );

        return [
            'id_token' => $token->toString(),
        ];
    }

    /**
     * Return true If this is an OpenID request
     *
     * @param ScopeEntityInterface[] $scopes
     *
     * @return bool
     */
    private static function isOpenIDRequest($scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope instanceof ScopeEntityInterface) {
                if ($scope->getIdentifier() === 'openid') {
                    return true;
                }
            }
        }

        return false;
    }
}
