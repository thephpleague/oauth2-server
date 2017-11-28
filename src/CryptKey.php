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

class CryptKey
{
    const RSA_KEY_PATTERN =
        '/^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----\n)(.|\n)+(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)$/';

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
        if (preg_match(self::RSA_KEY_PATTERN, $keyPath)) {
            $keyPath = $this->saveKeyToFile($keyPath);
        }

        if (strpos($keyPath, 'file://') !== 0) {
            $keyPath = 'file://' . $keyPath;
        }

        if (!file_exists($keyPath) || !is_readable($keyPath)) {
            throw new \LogicException(sprintf('Key path "%s" does not exist or is not readable', $keyPath));
        }

        if ($keyPermissionsCheck === true) {
            // Verify the permissions of the key
            $keyPathPerms = decoct(fileperms($keyPath) & 0777);
            if (in_array($keyPathPerms, ['600', '660'], true) === false) {
                // @codeCoverageIgnoreStart
                trigger_error(sprintf(
                    'Key file "%s" permissions are not correct, should be 600 or 660 instead of %s',
                    $keyPath,
                    $keyPathPerms
                ), E_USER_NOTICE);
                // @codeCoverageIgnoreEnd
            }
        }

        $this->keyPath = $keyPath;
        $this->passPhrase = $passPhrase;
    }

    /**
     * @param string $key
     *
     * @throws \RuntimeException
     *
     * @return string
     */
    private function saveKeyToFile($key)
    {
        $tmpDir = sys_get_temp_dir();
        $keyPath = $tmpDir . '/' . sha1($key) . '.key';

        if (!file_exists($keyPath) && !touch($keyPath)) {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('"%s" key file could not be created', $keyPath);
            // @codeCoverageIgnoreEnd
        }

        if (file_put_contents($keyPath, $key) === false) {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('Unable to write key file to temporary directory "%s"', $tmpDir);
            // @codeCoverageIgnoreEnd
        }

        if (chmod($keyPath, 0600) === false) {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('The key file "%s" file mode could not be changed with chmod to 600', $keyPath);
            // @codeCoverageIgnoreEnd
        }

        return 'file://' . $keyPath;
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
