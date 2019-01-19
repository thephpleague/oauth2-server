<?php declare(strict_types=1);

namespace League\OAuth2\Server\IdentifierGenerator;

use Error;
use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use TypeError;

class IdentifierGenerator implements IdentifierGeneratorInterface
{
    /**
     * {@inheritdoc}
     */
    public function generateUniqueIdentifier($length = 40)
    {
        try {
            return bin2hex(random_bytes($length));
            // @codeCoverageIgnoreStart
        } catch (TypeError $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred', $e);
        } catch (Error $e) {
            throw OAuthServerException::serverError('An unexpected error has occurred', $e);
        } catch (Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw OAuthServerException::serverError('Could not generate a random string', $e);
        }
        // @codeCoverageIgnoreEnd
    }
}
