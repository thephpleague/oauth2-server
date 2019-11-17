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

namespace League\OAuth2\Server;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Exception;
use LogicException;

trait CryptTrait
{
    /**
     * @var string|Key|null
     */
    protected $encryptionKey;

    /**
     * Encrypt data with encryptionKey.
     *
     * @param string $unencryptedData
     *
     * @throws LogicException
     *
     * @return string
     */
    protected function encrypt($unencryptedData)
    {
        try {
            if ($this->encryptionKey instanceof Key) {
                return Crypto::encrypt($unencryptedData, $this->encryptionKey);
            }

            if (\is_string($this->encryptionKey)) {
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
     * @param string $encryptedData
     *
     * @throws LogicException
     *
     * @return string
     */
    protected function decrypt($encryptedData)
    {
        try {
            if ($this->encryptionKey instanceof Key) {
                return Crypto::decrypt($encryptedData, $this->encryptionKey);
            }

            if (\is_string($this->encryptionKey)) {
                return Crypto::decryptWithPassword($encryptedData, $this->encryptionKey);
            }

            throw new LogicException('Encryption key not set when attempting to decrypt');
        } catch (Exception $e) {
            throw new LogicException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Set the encryption key
     *
     * @param string|Key $key
     */
    public function setEncryptionKey($key = null)
    {
        $this->encryptionKey = $key;
    }
}
