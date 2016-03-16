<?php
/**
 * Public/private key encryption.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server;

trait CryptTrait
{
    /**
     * @var string
     */
    protected $privateKeyPath;

    /**
     * @var string
     */
    protected $publicKeyPath;

    /**
     * Set path to private key.
     *
     * @param string $privateKeyPath
     */
    public function setPrivateKeyPath($privateKeyPath)
    {
        if (strpos($privateKeyPath, 'file://') !== 0) {
            $privateKeyPath = 'file://' . $privateKeyPath;
        }

        $this->privateKeyPath = $privateKeyPath;
    }

    /**
     * Set path to public key.
     *
     * @param string $publicKeyPath
     */
    public function setPublicKeyPath($publicKeyPath)
    {
        if (strpos($publicKeyPath, 'file://') !== 0) {
            $publicKeyPath = 'file://' . $publicKeyPath;
        }

        $this->publicKeyPath = $publicKeyPath;
    }

    /**
     * Encrypt data with a private key.
     *
     * @param string $unencryptedData
     *
     * @return string
     */
    protected function encrypt($unencryptedData)
    {
        $privateKey = openssl_pkey_get_private($this->privateKeyPath);
        $privateKeyDetails = @openssl_pkey_get_details($privateKey);
        if ($privateKeyDetails === null) {
            throw new \LogicException(sprintf('Could not get details of private key: %s', $this->privateKeyPath));
        }

        $chunkSize = ceil($privateKeyDetails['bits'] / 8) - 11;
        $output = '';

        while ($unencryptedData) {
            $chunk = substr($unencryptedData, 0, $chunkSize);
            $unencryptedData = substr($unencryptedData, $chunkSize);
            if (openssl_private_encrypt($chunk, $encrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING) === false) {
                // @codeCoverageIgnoreStart
                throw new \LogicException('Failed to encrypt data');
                // @codeCoverageIgnoreEnd
            }
            $output .= $encrypted;
        }
        openssl_free_key($privateKey);

        return base64_encode($output);
    }

    /**
     * Decrypt data with a public key.
     *
     * @param string $encryptedData
     *
     * @throws \LogicException
     *
     * @return string
     */
    protected function decrypt($encryptedData)
    {
        $publicKey = openssl_pkey_get_public($this->publicKeyPath);
        $publicKeyDetails = @openssl_pkey_get_details($publicKey);
        if ($publicKeyDetails === null) {
            throw new \LogicException(sprintf('Could not get details of public key: %s', $this->publicKeyPath));
        }

        $chunkSize = ceil($publicKeyDetails['bits'] / 8);
        $output = '';

        $encryptedData = base64_decode($encryptedData);

        while ($encryptedData) {
            $chunk = substr($encryptedData, 0, $chunkSize);
            $encryptedData = substr($encryptedData, $chunkSize);
            if (openssl_public_decrypt($chunk, $decrypted, $publicKey, OPENSSL_PKCS1_OAEP_PADDING) === false) {
                // @codeCoverageIgnoreStart
                throw new \LogicException('Failed to decrypt data');
                // @codeCoverageIgnoreEnd
            }
            $output .= $decrypted;
        }
        openssl_free_key($publicKey);

        return $output;
    }
}
