<?php

namespace RelationalExample\Config;

use Illuminate\Database\Capsule\Manager as Capsule;

include __DIR__.'/../vendor/autoload.php';

$capsule = new Capsule();

$capsule->addConnection([
    'driver'    => 'sqlite',
    'database'  => __DIR__.'/oauth2.sqlite3',
    'charset'   => 'utf8',
    'collation' => 'utf8_unicode_ci',
]);

$capsule->setAsGlobal();
