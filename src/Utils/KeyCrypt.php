<?php
/**
 * Public/private key encryption
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Utils;

class KeyCrypt
{
    /**
     * Encrypt data with a private key
     *
     * @param string $unencryptedData
     * @param string $pathToPrivateKey
     *
     * @return string
     */
    public static function encrypt($unencryptedData, $pathToPrivateKey)
    {
        $privateKey = openssl_pkey_get_private($pathToPrivateKey);
        $privateKeyDetails = @openssl_pkey_get_details($privateKey);
        if ($privateKeyDetails === null) {
            throw new \LogicException(sprintf('Could not get details of private key: %s', $pathToPrivateKey));
        }

        $chunkSize = ceil($privateKeyDetails['bits'] / 8) - 11;
        $output = '';

        while ($unencryptedData) {
            $chunk = substr($unencryptedData, 0, $chunkSize);
            $unencryptedData = substr($unencryptedData, $chunkSize);
            if (openssl_private_encrypt($chunk, $encrypted, $privateKey) === false) {
                throw new \LogicException('Failed to encrypt data');
            }
            $output .= $encrypted;
        }
        openssl_free_key($privateKey);

        return base64_encode($output);
    }

    /**
     * Decrypt data with a public key
     *
     * @param string $encryptedData
     * @param string $pathToPublicKey
     *
     * @return string
     */
    public static function decrypt($encryptedData, $pathToPublicKey)
    {
        $publicKey = openssl_pkey_get_public($pathToPublicKey);
        $publicKeyDetails = @openssl_pkey_get_details($publicKey);
        if ($publicKeyDetails === null) {
            throw new \LogicException(sprintf('Could not get details of public key: %s', $pathToPublicKey));
        }

        $chunkSize = ceil($publicKeyDetails['bits'] / 8);
        $output = '';

        $encryptedData = base64_decode($encryptedData);

        while ($encryptedData) {
            $chunk = substr($encryptedData, 0, $chunkSize);
            $encryptedData = substr($encryptedData, $chunkSize);
            if (openssl_public_decrypt($chunk, $decrypted, $publicKey) === false) {
                throw new \LogicException('Failed to decrypt data');
            }
            $output .= $decrypted;
        }
        openssl_free_key($publicKey);

        return $output;
    }
}
