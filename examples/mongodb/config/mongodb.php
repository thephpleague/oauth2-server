<?php

namespace MongoDBExample\Config;

use Doctrine\MongoDB\Connection;
use Doctrine\ODM\MongoDB\Configuration;
use Doctrine\ODM\MongoDB\DocumentManager;
use Doctrine\ODM\MongoDB\Mapping\Driver\AnnotationDriver;

/**
 * Doctrine DocumentManager for MongoDB
 */
class DM {
    /**
     * @var \Doctrine\ODM\MongoDB\DocumentManager
     */
    private static $dm;

    /**
     * get a DocumentManager instance
     */
    public static function get() {

        if(!self::$dm) {
            if ( ! file_exists($file = dirname(__DIR__).'/vendor/autoload.php')) {
                throw new RuntimeException('Install dependencies to run this script.');
            }

            $connection = new Connection();

            $config = new Configuration();
            $config->setProxyDir(dirname(__DIR__) . '/Proxies');
            $config->setProxyNamespace('Proxies');
            $config->setHydratorDir(dirname(__DIR__) . '/Hydrators');
            $config->setHydratorNamespace('Hydrators');
            $config->setDefaultDB('oauth2');
            $config->setMetadataDriverImpl(AnnotationDriver::create(dirname(__DIR__) . '/Documents'));

            AnnotationDriver::registerAnnotationClasses();

            self::$dm = DocumentManager::create($connection, $config);
        }

        return self::$dm;
    }
}