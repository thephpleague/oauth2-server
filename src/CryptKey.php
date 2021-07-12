<?php
/**
 * Cryptography key holder.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use LogicException;

class CryptKey
{
    /** @deprecated left for backward compatibility check */
    const RSA_KEY_PATTERN =
        '/^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----)\R.*(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)\R?$/s';

    private const FILE_PREFIX = 'file://';

    /**
     * @var string Key contents
     */
    protected $keyContents;

    /**
     * @var string
     */
    protected $keyPath;

    /**
     * @var null|string
     */
    protected $passPhrase;

    /**
     * @param string      $keyPath
     * @param null|string $passPhrase
     * @param bool        $keyPermissionsCheck
     */
    public function __construct($keyPath, $passPhrase = null, $keyPermissionsCheck = true)
    {
        $this->passPhrase = $passPhrase;

        if (\strpos($keyPath, self::FILE_PREFIX) !== 0 && $this->isValidKey($keyPath, $this->passPhrase ?? '')) {
            $this->keyContents = $keyPath;
            $this->keyPath = '';
            // There's no file, so no need for permission check.
            $keyPermissionsCheck = false;
        } elseif (\is_file($keyPath)) {
            if (\strpos($keyPath, self::FILE_PREFIX) !== 0) {
                $keyPath = self::FILE_PREFIX . $keyPath;
            }

            if (!\is_readable($keyPath)) {
                throw new LogicException(\sprintf('Key path "%s" does not exist or is not readable', $keyPath));
            }
            $this->keyContents = \file_get_contents($keyPath);
            $this->keyPath = $keyPath;
            if (!$this->isValidKey($this->keyContents, $this->passPhrase ?? '')) {
                throw new LogicException('Unable to read key from file ' . $keyPath);
            }
        } else {
            throw new LogicException('Unable to read key from file ' . $keyPath);
        }

        if ($keyPermissionsCheck === true) {
            // Verify the permissions of the key
            $keyPathPerms = \decoct(\fileperms($this->keyPath) & 0777);
            if (\in_array($keyPathPerms, ['400', '440', '600', '640', '660'], true) === false) {
                \trigger_error(
                    \sprintf(
                        'Key file "%s" permissions are not correct, recommend changing to 600 or 660 instead of %s',
                        $this->keyPath,
                        $keyPathPerms
                    ),
                    E_USER_NOTICE
                );
            }
        }
    }

    /**
     * Get key contents
     *
     * @return string Key contents
     */
    public function getKeyContents(): string
    {
        return $this->keyContents;
    }

    /**
     * Validate key contents.
     *
     * @param string $contents
     * @param string $passPhrase
     *
     * @return bool
     */
    private function isValidKey($contents, $passPhrase)
    {
        $pkey = \openssl_pkey_get_private($contents, $passPhrase) ?: \openssl_pkey_get_public($contents);
        if ($pkey === false) {
            return false;
        }
        $details = \openssl_pkey_get_details($pkey);

        return $details !== false && \in_array(
            $details['type'] ?? -1,
            [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC],
            true
        );
    }

    /**
     * Retrieve key path.
     *
     * @return string
     */
    public function getKeyPath()
    {
        return $this->keyPath;
    }

    /**
     * Retrieve key pass phrase.
     *
     * @return null|string
     */
    public function getPassPhrase()
    {
        return $this->passPhrase;
    }
}
