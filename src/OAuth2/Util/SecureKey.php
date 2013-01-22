<?php

namespace OAuth2\Util;

class SecureKey
{
    public static function make($len = 42)
    {
        // We generate twice as many bytes here because we want to ensure we have
        // enough after we base64 encode it to get the length we need because we
        // take out the "/", "+", and "=" characters.
        $bytes = openssl_random_pseudo_bytes($len * 2, $strong);

        // We want to stop execution if the key fails because, well, that is bad.
        if ($bytes === false || $strong === false) {
            throw new Exception('Error Generating Key');
        }

        return substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $len);
    }
}