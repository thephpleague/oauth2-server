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
     */
    public function __construct($keyPath, $passPhrase = null)
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
        $keyPath = sys_get_temp_dir() . '/' . sha1($key) . '.key';

        if (!file_exists($keyPath) && !touch($keyPath)) {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('"%s" key file could not be created', $keyPath);
            // @codeCoverageIgnoreEnd
        }

        file_put_contents($keyPath, $key);

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
