<?php
/**
 * Created by PhpStorm.
 * User: jderay
 * Date: 3/11/14
 * Time: 12:22 PM
 */

namespace League\OAuth2\Server\Util\KeyAlgorithm;


interface KeyAlgorithmInterface
{
    public function make($len = 40);
} 