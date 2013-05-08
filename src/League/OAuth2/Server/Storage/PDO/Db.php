<?php

namespace League\OAuth2\Server\Storage\PDO;

class Db
{
    public function __construct($dsn = '')
    {
        $db = \ezcDbFactory::create($dsn);
        \ezcDbInstance::set($db);
    }
}