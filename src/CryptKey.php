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

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use LogicException;

class CryptKey
{
    const RSA_KEY_PATTERN =
        '/^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----)\R.*(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)\R?$/s';

    const FILE_PREFIX = 'file://';

    /**
     * @var string
     */
    protected $keyPath;

    /**
     * @var null|string
     */
    protected $passPhrase;

    /**
     * @param string $keyPath
     * @param null|string $passPhrase
     * @param bool $keyPermissionsCheck
     */
    public function __construct($keyPath, $passPhrase = null, $keyPermissionsCheck = true)
    {
        $this->keyPath = $keyPath;
        $this->passPhrase = $passPhrase;

        if (is_file($this->keyPath) && !$this->isFilePath()) {
            $this->keyPath = self::FILE_PREFIX . $this->keyPath;
        }

        if ($this->isFilePath()) {
            if (!\file_exists($keyPath) || !\is_readable($keyPath)) {
                throw new LogicException(\sprintf('Key path "%s" does not exist or is not readable', $keyPath));
            }

            if ($keyPermissionsCheck === true && PHP_OS_FAMILY !== 'Windows') {
                // Verify the permissions of the key
                $keyPathPerms = \decoct(\fileperms($keyPath) & 0777);
                if (\in_array($keyPathPerms, ['400', '440', '600', '640', '660'], true) === false) {
                    \trigger_error(
                        \sprintf(
                            'Key file "%s" permissions are not correct, recommend changing to 600 or 660 instead of %s',
                            $keyPath,
                            $keyPathPerms
                        ),
                        E_USER_NOTICE
                    );
                }
            }
        } else {
            $rsaMatch = \preg_match(static::RSA_KEY_PATTERN, $this->keyPath);
            if ($rsaMatch === 0) {
                throw new LogicException('This is not a RSA key');
            }

            if ($rsaMatch === false) {
                throw new \RuntimeException(
                    \sprintf('PCRE error [%d] encountered during key match attempt', \preg_last_error())
                );
            }
        }
    }

    public function isFilePath(): bool
    {
        return \strpos($this->keyPath, self::FILE_PREFIX) === 0;
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

    /**
     * Create signer key
     *
     * @internal Remove when the JWT configuration is moved to the dependency injection container
     *
     * @return \Lcobucci\JWT\Signer\Key
     */
    public function createSignerKey(): \Lcobucci\JWT\Signer\Key
    {
        if ($this->isFilePath()) {
            return LocalFileReference::file($this->keyPath, $this->passPhrase ?? '');
        }

        return InMemory::plainText($this->keyPath, $this->passPhrase ?? '');
    }
}
