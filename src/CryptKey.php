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

declare(strict_types=1);

namespace League\OAuth2\Server;

use LogicException;
use OpenSSLAsymmetricKey;

use function decoct;
use function file_get_contents;
use function fileperms;
use function in_array;
use function is_file;
use function is_readable;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function sprintf;
use function trigger_error;

class CryptKey implements CryptKeyInterface
{
    private const FILE_PREFIX = 'file://';

    /**
     * @var string Key contents
     */
    protected string $keyContents;

    protected string $keyPath;

    public function __construct(string $keyPath, protected ?string $passPhrase = null, bool $keyPermissionsCheck = true)
    {
        if (str_starts_with($keyPath, self::FILE_PREFIX) === false && $this->isValidKey($keyPath, $this->passPhrase ?? '')) {
            $this->keyContents = $keyPath;
            $this->keyPath = '';
            // There's no file, so no need for permission check.
            $keyPermissionsCheck = false;
        } elseif (is_file($keyPath)) {
            if (str_starts_with($keyPath, self::FILE_PREFIX) === false) {
                $keyPath = self::FILE_PREFIX . $keyPath;
            }

            if (!is_readable($keyPath)) {
                throw new LogicException(sprintf('Key path "%s" does not exist or is not readable', $keyPath));
            }

            $keyContents = file_get_contents($keyPath);

            if ($keyContents === false) {
                throw new LogicException('Unable to read key from file ' . $keyPath);
            }

            $this->keyContents = $keyContents;
            $this->keyPath = $keyPath;

            if (!$this->isValidKey($this->keyContents, $this->passPhrase ?? '')) {
                throw new LogicException('Unable to read key from file ' . $keyPath);
            }
        } else {
            throw new LogicException('Invalid key supplied');
        }

        if ($keyPermissionsCheck === true && PHP_OS_FAMILY !== 'Windows') {
            // Verify the permissions of the key
            $keyPathPerms = decoct(fileperms($this->keyPath) & 0777);
            if (in_array($keyPathPerms, ['400', '440', '600', '640', '660'], true) === false) {
                trigger_error(
                    sprintf(
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
     * {@inheritdoc}
     */
    public function getKeyContents(): string
    {
        return $this->keyContents;
    }

    /**
     * Validate key contents.
     */
    private function isValidKey(string $contents, string $passPhrase): bool
    {
        $privateKey = openssl_pkey_get_private($contents, $passPhrase);

        $key = $privateKey instanceof OpenSSLAsymmetricKey ? $privateKey : openssl_pkey_get_public($contents);

        if ($key === false) {
            return false;
        }

        $details = openssl_pkey_get_details($key);

        return $details !== false && in_array(
            $details['type'] ?? -1,
            [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC],
            true
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyPath(): string
    {
        return $this->keyPath;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassPhrase(): ?string
    {
        return $this->passPhrase;
    }
}
