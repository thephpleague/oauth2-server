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
use RuntimeException;

class CryptKey
{
    /** @deprecated left for backward compatibility check */
    const RSA_KEY_PATTERN =
        '/^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----)\R.*(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)\R?$/s';

    private const FILE_PREFIX = 'file://';

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

        if (\is_file($keyPath)) {
            if (\strpos($keyPath, self::FILE_PREFIX) !== 0) {
                $keyPath = self::FILE_PREFIX . $keyPath;
            }

            if (!\is_readable($keyPath)) {
                throw new LogicException(\sprintf('Key path "%s" does not exist or is not readable', $keyPath));
            }
            $isFileKey = true;
            $contents = \file_get_contents($keyPath);
            $this->keyPath = $keyPath;
        } else {
            $isFileKey = false;
            $contents = $keyPath;
            $this->keyPath = $this->saveKeyToFile($keyPath);
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

        if (!$this->isValidKey($contents, $this->passPhrase ?? '')) {
            throw new LogicException('Unable to read key' . ($isFileKey ? " from file $keyPath" : ''));
        }
    }

    /**
     * @param string $key
     *
     * @throws RuntimeException
     *
     * @return string
     */
    private function saveKeyToFile($key)
    {
        $tmpDir = \sys_get_temp_dir();
        $keyPath = $tmpDir . '/' . \sha1($key) . '.key';

        if (\file_exists($keyPath)) {
            return self::FILE_PREFIX . $keyPath;
        }

        if (\file_put_contents($keyPath, $key) === false) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(\sprintf('Unable to write key file to temporary directory "%s"', $tmpDir));
            // @codeCoverageIgnoreEnd
        }

        if (\chmod($keyPath, 0600) === false) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(\sprintf('The key file "%s" file mode could not be changed with chmod to 600', $keyPath));
            // @codeCoverageIgnoreEnd
        }

        return self::FILE_PREFIX . $keyPath;
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
