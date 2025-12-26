<?php

declare(strict_types=1);

namespace League\OAuth2\Server\Repositories;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

/**
 * Exmaple implemnation of IdTokenRepositoryInterface
 *
 * @author Marc Riemer <mail@marcriemer.de>
 * @license http://opensource.org/licenses/MIT MIT
 */
class IdTokenRepository implements IdTokenRepositoryInterface
{
    public function __construct(private string $issuedBy, private ?string $nonce = null)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getBuilder(AccessTokenEntityInterface $accessToken): Builder
    {
        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy($this->issuedBy)
            ->issuedAt(new DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($accessToken->getUserIdentifier());

        if ($this->nonce) {
            $builder->withClaim('nonce', $this->nonce);
        }

        return $builder;
    }
}
