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
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\NoKeyLoadedException;
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
        $this->keyPath = $keyPath;
        $this->passPhrase = $passPhrase;

        if (\is_file($this->keyPath) && !$this->isFilePath()) {
            $this->keyPath = self::FILE_PREFIX . $this->keyPath;
        }

        if ($this->isFilePath()) {
            if (!\file_exists($this->keyPath) || !\is_readable($this->keyPath)) {
                throw new LogicException(\sprintf('Key path "%s" does not exist or is not readable', $this->keyPath));
            }

            $contents = \file_get_contents($this->keyPath);
        } else {
            $contents = $keyPath;
        }

        if ($this->isValidKey($contents, $this->passPhrase ?? '')) {
            if (!$this->isFilePath()) {
                $this->keyPath = $this->saveKeyToFile($keyPath);
            }
        } else {
            throw new LogicException('Unable to read key' . ($this->isFilePath() ? " from file $keyPath" : ''));
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
        try {
            RSA::load($contents, $passPhrase);

            return true;
        } catch (NoKeyLoadedException $e) {
        }

        try {
            EC::load($contents, $passPhrase);

            return true;
        } catch (NoKeyLoadedException $e) {
        }

        return false;
    }

    /**
     * Checks whether the key is a file.
     *
     * @return bool
     */
    private function isFilePath()
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
}
