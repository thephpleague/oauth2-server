<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Entities\Traits;

trait AuthCodeTrait
{
    protected ?string $redirectUri = null;
    
    /**
     * The code challenge (if provided)
     */
    protected ?string $codeChallenge;

    /**
     * The code challenge method (if provided)
     */
    protected ?string $codeChallengeMethod;

    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(?string $uri): void
    {
        $this->redirectUri = $uri;
    }

    public function getCodeChallenge(): ?string
    {
        return $this->codeChallenge ?? null;
    }

    public function setCodeChallenge(?string $codeChallenge): void
    {
        $this->codeChallenge = $codeChallenge;
    }

    public function getCodeChallengeMethod(): ?string
    {
        return $this->codeChallengeMethod ?? null;
    }

    public function setCodeChallengeMethod(?string $codeChallengeMethod): void
    {
        $this->codeChallengeMethod = $codeChallengeMethod;
    }
}
