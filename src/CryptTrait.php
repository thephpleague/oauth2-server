<?php

/**
 * Encrypt/decrypt with encryptionKey.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use Exception;
use InvalidArgumentException;
use LogicException;

use function is_string;

trait CryptTrait
{
    protected string|Key|null $encryptionKey = null;

    /**
     * Encrypt data with encryptionKey.
     *
     * @throws LogicException
     */
    protected function encrypt(string $unencryptedData): string
    {
        try {
            if ($this->encryptionKey instanceof Key) {
                return Crypto::encrypt($unencryptedData, $this->encryptionKey);
            }

            if (is_string($this->encryptionKey)) {
                return Crypto::encryptWithPassword($unencryptedData, $this->encryptionKey);
            }

            throw new LogicException('Encryption key not set when attempting to encrypt');
        } catch (Exception $e) {
            throw new LogicException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypt data with encryptionKey.
     *
     * @throws LogicException
     */
    protected function decrypt(string $encryptedData): string
    {
        try {
            if ($this->encryptionKey instanceof Key) {
                return Crypto::decrypt($encryptedData, $this->encryptionKey);
            }

            if (is_string($this->encryptionKey)) {
                return Crypto::decryptWithPassword($encryptedData, $this->encryptionKey);
            }

            throw new LogicException('Encryption key not set when attempting to decrypt');
        } catch (WrongKeyOrModifiedCiphertextException $e) {
            $exceptionMessage = 'The authcode or decryption key/password used '
                . 'is not correct';

            throw new InvalidArgumentException($exceptionMessage, 0, $e);
        } catch (EnvironmentIsBrokenException $e) {
            $exceptionMessage = 'Auth code decryption failed. This is likely '
                . 'due to an environment issue or runtime bug in the '
                . 'decryption library';

            throw new LogicException($exceptionMessage, 0, $e);
        } catch (Exception $e) {
            throw new LogicException($e->getMessage(), 0, $e);
        }
    }

    public function setEncryptionKey(Key|string|null $key = null): void
    {
        $this->encryptionKey = $key;
    }
}
