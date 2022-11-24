<?php

namespace League\OAuth2\Server\ResponseTypes;

use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\ClaimExtractor;
use League\OAuth2\Server\Entities\ClaimSetEntryInterface;
use League\OAuth2\Server\IdTokenClaimsCreated;
use League\OAuth2\Server\Repositories\ClaimSetRepositoryInterface;
use League\OAuth2\Server\RequestEvent;

/**
 * OpenidConfigurationResponse
 * 
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @author Steve Rhoades <sedonami@gmail.com>
 * @author Marc Riemer <mail@marcriemer.de>
 */
class IdTokenResponse extends BearerTokenResponse
{
    use EmitterAwareTrait;

    public function __construct(
        protected ServerRequestInterface $request, 
        protected ClaimSetRepositoryInterface $claimRepository, 
        protected ClaimExtractor $extractor)
    {}

    /**
     * @param AccessTokenEntityInterface $accessToken
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        // Onyly add id_token to openid requests
        if (!in_array("openid", $accessToken->getScopes())) {
            return [];
        }

        $claimSet = $this->claimRepository->getClaimSetByUserIdentifier($accessToken->getUserIdentifier());
        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy(sprintf("%s://%s", 
                $this->request->getUri()->getScheme(), $this->request->getUri()->getHost()))
            ->issuedAt(new \DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($accessToken->getUserIdentifier());

        if ($claimSet instanceof ClaimSetEntryInterface) {
            foreach ($this->extractor->extract($accessToken->getScopes(), $claimSet->getClaims())as $claimName => $claimValue) {
                $builder->withClaim($claimName, $claimValue);
            }
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
        if (array_key_exists($nonce = "nonce", $this->request->getQueryParams())) {
            $builder->withClaim($nonce, $this->request->getQueryParams()[$nonce]);
        }

        $this->getEmitter()->emit(
            new IdTokenClaimsCreated(RequestEvent::ID_TOKEN_CLAIMS_CREATED, $this->request, $builder));

        return [
            'id_token' => $builder->getToken(new Sha256(),
                InMemory::file($this->privateKey->getKeyPath(), (string)$this->privateKey->getPassPhrase()))->toString()
        ];
    }
}
