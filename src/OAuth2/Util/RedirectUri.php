<?php

namespace OAuth2\Util;

class RedirectUri
{
    public static function make($uri, $params = array(), $queryDelimeter = '?')
    {
        $uri .= (strstr($uri, $queryDelimeter) === false) ? $queryDelimeter : '&';
        return $uri.http_build_query($params);
    }
}