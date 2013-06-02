# Changelog

## 2.1.1 (released 2013-06-02)

* Added conditional `isValid()` flag to check for Authorization header only (thanks @alexmcroberts)
* Fixed semantic meaning of `requireScopeParam()` and `requireStateParam()` by changing their default value to true
* Updated some duff docblocks
* Corrected array key call in Resource.php (Issue #63)

## 2.1 (released 2013-05-10)

* Moved zetacomponents/database to "suggest" in composer.json. If you rely on this feature you now need to include " zetacomponents/database" into "require" key in your own composer.json. (Issue #51)
* New method in Refresh grant called `rotateRefreshTokens()`. Pass in `true` to issue a new refresh token each time an access token is refreshed. This parameter needs to be set to true in order to request reduced scopes with the new access token. (Issue #47)
* Rename `key` column in oauth_scopes table to `scope` as `key` is a reserved SQL word. (Issue #45)
* The `scope` parameter is no longer required by default as per the RFC. (Issue #43)
* You can now set multiple default scopes by passing an array into `setDefaultScope()`. (Issue #42)
* The password and client credentials grants now allow for multiple sessions per user. (Issue #32)
* Scopes associated to authorization codes are not held in their own table (Issue #44)
* Database schema updates.

## 2.0.5 (released 2013-05-09)

* Fixed `oauth_session_token_scopes` table primary key
* Removed `DEFAULT ''` that has slipped into some tables
* Fixed docblock for `SessionInterface::associateRefreshToken()`

## 2.0.4 (released 2013-05-09)

* Renamed primary key in oauth_client_endpoints table
* Adding missing column to oauth_session_authcodes
* SECURITY FIX: A refresh token should be bound to a client ID

## 2.0.3 (released 2013-05-08)

* Fixed a link to code in composer.json

## 2.0.2 (released 2013-05-08)

* Updated README with wiki guides
* Removed `null` as default parameters in some methods in the storage interfaces
* Fixed license copyright

## 2.0.0 (released 2013-05-08)

**If you're upgrading from v1.0.8 there are lots of breaking changes**

* Rewrote the session storage interface from scratch so methods are more obvious
* Included a PDO driver which implements the storage interfaces so the library is more "get up and go"
* Further normalised the database structure so all sessions no longer contain infomation related to authorization grant (which may or may not be enabled)
* A session can have multiple associated access tokens
* Induvidual grants can have custom expire times for access tokens
* Authorization codes now have a TTL of 10 minutes by default (can be manually set)
* Refresh tokens now have a TTL of one week by default (can be manually set)
* The client credentials grant will no longer gives out refresh tokens as per the specification

## 1.0.8 (released 2013-03-18)

* Fixed check for required state parameter
* Fixed check that user's credentials are correct in Password grant

## 1.0.7 (released 2013-03-04)

* Added method `requireStateParam()`
* Added method `requireScopeParam()`

## 1.0.6 (released 2013-02-22)

* Added links to tutorials in the README
* Added missing `state` parameter request to the `checkAuthoriseParams()` method.

## 1.0.5 (released 2013-02-21)

* Fixed the SQL example for SessionInterface::getScopes()

## 1.0.3 (released 2013-02-20)

* Changed all instances of the "authentication server" to "authorization server"

## 1.0.2 (released 2013-02-20)

* Fixed MySQL create table order
* Fixed version number in composer.json

## 1.0.1 (released 2013-02-19)

* Updated AuthServer.php to use `self::getParam()`

## 1.0.0 (released 2013-02-15)

* First major release