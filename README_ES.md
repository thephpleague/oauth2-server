# Servidor OAuth 2.0 para PHP [leer en ingles (read in english)](https://github.com/thephpleague/oauth2-server/blob/master/README.md).

[![Latest Version](http://img.shields.io/packagist/v/league/oauth2-server.svg?style=flat-square)](https://github.com/thephpleague/oauth2-server/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://github.com/thephpleague/oauth2-server/workflows/tests/badge.svg)](https://github.com/thephpleague/oauth2-server/actions)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server)
[![Total Downloads](https://img.shields.io/packagist/dt/league/oauth2-server.svg?style=flat-square)](https://packagist.org/packages/league/oauth2-server)

`league/oauth2-server` Cumple con los estándares de implementación que debe tener un servidor de autorización [OAuth 2.0](https://tools.ietf.org/html/rfc6749), esta escrito en PHP, trabajar con el puede ser trivial, es facil configurarlo para proteger las APIS con tokens de acceso, tambien permitir a los clientes puedan solicitar nuevos tokens, los cuales pueden ser actualizados.

Actualmente tiene soporte para los siguientes tipos de consesión:

* Concesión por código de autorización (Authorization code grant).
* Concesión implícita(implicit grant).
* Concesión por credenciales de cliente (Client credentials grant)
* Concesión de credenciales de contraseña del propietario del recurso(Resource owner password credentials grant).
* Actualización de la Concesión. (Refresh grant).

Se siguientes RFCś (Request for Comments que en español significa *Solicitud de comentarios.* ) son implementados:

* [RFC6749 "OAuth 2.0"](https://tools.ietf.org/html/rfc6749)
* [RFC6750 "Framework de Autorización: uso del token por el portador (The OAuth 2.0 Authorization Framework: Bearer Token Usage)"](https://tools.ietf.org/html/rfc6750)
* [RFC7519 "JSON Web Token (JWT)"](https://tools.ietf.org/html/rfc7519)
* [RFC7636 "Comprobación de la clave por el código de intercambio emitido por el cliente público de OAuth (Proof Key for Code Exchange by OAuth Public Clients) "](https://tools.ietf.org/html/rfc7636)

Esta libraría fue creada por Alex Bilbie. Encuentralo en Twitter como [@alexbilbie](https://twitter.com/alexbilbie).

## Requerimientos.

La ultima versión del *Servidor OAuth 2.0 para PHP* es compatible con las siguientes versiones de PHP :

* PHP 7.2
* PHP 7.3
* PHP 7.4
* PHP 8.0

Es necesario contar con las extensiones de `openssl` y `json`.
Todos los mensajes HTTP que pasan al servidor, deben ser [compatibles con PSR-7](https://www.php-fig.org/psr/psr-7/). Esto garantizara la permeabilidad con otros paquetes y Frameworks.

## Instalación desde Composer.

Nos dirigimos a la carpeta del proyecto donde se usara el *Servidor OAuth 2.0 para PHP* desde una terminal. y escribimos:

```
composer require league/oauth2-server
```

## Documentación.

La documentación de esta libreria la puedne encontrar en [https://oauth2.thephpleague.com](https://oauth2.thephpleague.com) (esta en ingles).
Pueden contribuir a la documentación en la [rama gh-pages](https://github.com/thephpleague/oauth2-server/tree/gh-pages/).

## Pruebas (Testeo).

Esta libreria usa [PHPUnit](https://phpunit.de/) para realizar pruebas unitarias.

```
vendor/bin/phpunit
```

## Integraticiones Continuas.

Nosotros usamos las [Acciones de Github](https://github.com/features/actions), [Scrutinizer](https://scrutinizer-ci.com/), y [StyleCI](https://styleci.io/) para continuar la integración. Si quieres conocer más, revisa [nuestra](https://github.com/thephpleague/oauth2-server/blob/master/.github/workflows/tests.yml) [configuración](https://github.com/thephpleague/oauth2-server/blob/master/.scrutinizer.yml) de [archivos](https://github.com/thephpleague/oauth2-server/blob/master/.styleci.yml).

## Integraciones Comunitarias.

* [Drupal](https://www.drupal.org/project/simple_oauth)
* [Laravel Passport](https://github.com/laravel/passport)
* [OAuth 2 Server for CakePHP 3](https://github.com/uafrica/oauth-server)
* [OAuth 2 Server for Mezzio](https://github.com/mezzio/mezzio-authentication-oauth2)
* [Trikoder OAuth 2 Bundle (Symfony)](https://github.com/trikoder/oauth2-bundle)
* [Heimdall for CodeIgniter 4](https://github.com/ezralazuardy/heimdall)

## Registros de cambios (Changelog).

Mira los [registros de cambio del projecto](https://github.com/thephpleague/oauth2-server/blob/master/CHANGELOG.md)

## Contribuir

Toda contribución es bienvenida. Para ver más detalles revisa [CONTRIBUTING.md](https://github.com/thephpleague/oauth2-server/blob/master/CONTRIBUTING.md) y el [CODIGO DE_CONDUCTA.md](https://github.com/thephpleague/oauth2-server/blob/master/CODE_OF_CONDUCT.md).

## Soporte

El seguimiento de Errores (Bugs) y dudas sobre alguna función o caracteristica, se realiza en [GitHub](https://github.com/thephpleague/oauth2-server/issues).

Si tienes alguna pregunta sobre OAuth _por favor_ abre un nuevo tema ahi; **No envien** correos electronicos ni cuentas personales, no se realizara ningun seguimiento privado a sus dudas y errores, somos una comunidad y hay que fomentarla para crecer, al igual que tu, alguien más puede llegar a tener la misma duda, generemos contenido como comunidad.

## Seguridad

Si descubres algún problema relacionado con la seguridad, envía un correo electrónico a `andrew@noexceptions.io`en vez de crear un tema en el apartado de [GitHub](https://github.com/thephpleague/oauth2-server/issues).


## Licencia

Esta librería se publica bajo la licencia MIT. Consulte el archivo [LICENSE](https://github.com/thephpleague/oauth2-server/blob/master/LICENSE) para conocer más detalles.

## Creditos

El desarrollo y mantenimiento del codigo ha sido realizado principalmente por [Andy Millington](https://twitter.com/Sephster).

Entre el 2012 y el 2017 esta librería fue desarrollada y recibio mantenimineto por [Alex Bilbie](https://alexbilbie.com/).

El __Servidor OAuth 2.0 para PHP__ es uno de los muchos proyectos porporcionados por __The PHP League__. Para conocer más, visita [nuestro sitio web](https://thephpleague.com) (ingles).

Damos un agradecimineto especial a [todos estos increíbles colaboradores](https://github.com/thephpleague/oauth2-server/contributors).

Tambien queremos agradecer a [Mozilla Secure Open Source Fund](https://wiki.mozilla.org/MOSS/Secure_Open_Source) por financiar una auditoría de seguridad de esta librería.

El código inicial se desarrolló como parte de [Linkey](http://linkey.blogs.lincoln.ac.uk) projecto que fue fundado por [JISC](http://jisc.ac.uk) atraves del programa de gestion de accesos e indentidad (the Access and Identity Management programme).
