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
     */
    public function __construct($keyPath, $passPhrase = null)
    {
        if (strpos($keyPath, '://') === false) {
            $keyPath = 'file://' . $keyPath;
        }

        if (!file_exists($keyPath) || !is_readable($keyPath)) {
            throw new \LogicException(sprintf('Key path "%s" does not exist or is not readable', $keyPath));
        }

        $this->keyPath = $keyPath;
        $this->passPhrase = $passPhrase;
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
     * @param $key
     * @param null $passPhrase
     * @return CryptKey
     */
    public static function fromString($key, $passPhrase = null)
    {
        $keyPath = sys_get_temp_dir() . '/' . sha1($key) . '.key';

        if (!file_exists($keyPath) && !touch($keyPath)) {
            // @codeCoverageIgnoreStart
            throw new \RuntimeException('"%s" key file could not be created', $keyPath);
            // @codeCoverageIgnoreEnd
        }

        file_put_contents($keyPath, $key);

        return new static('file://' . $keyPath, $passPhrase);
    }
}
