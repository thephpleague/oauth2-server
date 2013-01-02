<?php

if ( ! @include_once __DIR__ . '/../vendor/autoload.php')
{
    exit("You must set up the project dependencies, run the following commands:\n> wget http://getcomposer.org/composer.phar\n> php composer.phar install\n");
}