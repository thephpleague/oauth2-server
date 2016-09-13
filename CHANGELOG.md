# Changelog

## 4.1.6 (released 2016-09-13)

* Less restrictive on Authorization header check (Issue #652)

## 4.1.5 (released 2016-01-04)

* Enable Symfony 3.0 support (#412)

## 4.1.4 (released 2015-11-13)

* Fix for determining access token in header (Issue #328)
* Refresh tokens are now returned for MAC responses (Issue #356)
* Added integration list to readme (Issue #341)
* Expose parameter passed to exceptions (Issue #345)
* Removed duplicate routing setup code (Issue #346)
* Docs fix (Issues #347, #360, #380)
* Examples fix (Issues #348, #358)
* Fix typo in docblock (Issue #352)
* Improved timeouts for MAC tokens (Issue #364)
* `hash_hmac()` should output raw binary data, not hexits (Issue #370)
* Improved regex for matching all Base64 characters (Issue #371)
* Fix incorrect signature parameter (Issue #372)
* AuthCodeGrant and RefreshTokenGrant don't require client_secret (Issue #377)
* Added priority argument to event listener (Issue #388)

## 4.1.3 (released 2015-03-22)

* Docblock, namespace and inconsistency fixes (Issue #303)
* Docblock type fix (Issue #310)
* Example bug fix (Issue #300)
* Updated league/event to ~2.1 (Issue #311)
* Fixed missing session scope (Issue #319)
* Updated interface docs (Issue #323)
* `.travis.yml` updates

## 4.1.2 (released 2015-01-01)

* Remove side-effects in hash_equals() implementation (Issue #290)

## 4.1.1 (released 2014-12-31)

* Changed `symfony/http-foundation` dependency version to `~2.4` so package can be installed in Laravel `4.1.*`

## 4.1.0 (released 2014-12-27)

* Added MAC token support (Issue #158)
* Fixed example init code (Issue #280)
* Toggle refresh token rotation (Issue #286)
* Docblock fixes

## 4.0.5 (released 2014-12-15)

* Prevent duplicate session in auth code grant (Issue #282)

## 4.0.4 (released 2014-12-03)

* Ensure refresh token hasn't expired (Issue #270)

## 4.0.3 (released 2014-12-02)

* Fix bad type hintings (Issue #267)
* Do not forget to set the expire time (Issue #268)

## 4.0.2 (released 2014-11-21)

* Improved interfaces (Issue #255)
* Learnt how to spell delimiter and so `getScopeDelimiter()` and `setScopeDelimiter()` methods have been renamed
* Docblock improvements (Issue #254)

## 4.0.1 (released 2014-11-09)

* Alias the master branch in composer.json (Issue #243)
* Numerous PHP CodeSniffer fixes (Issue #244)
* .travis.yml update (Issue #245)
* The getAccessToken method should return an AccessTokenEntity object instead of a string in ResourceServer.php (#246)

## 4.0.0 (released 2014-11-08)

* Complete rewrite
* Check out the documentation - [http://oauth2.thephpleague.com](http://oauth2.thephpleague.com)

## 3.2.0 (released 2014-04-16)

* Added the ability to change the algorithm that is used to generate the token strings (Issue #151)

## 3.1.2 (released 2014-02-26)

* Support Authorization being an environment variable. [See more](http://fortrabbit.com/docs/essentials/quirks-and-constraints#authorization-header)

## 3.1.1 (released 2013-12-05)

* Normalize headers when `getallheaders()` is available (Issues #108 and #114)

## 3.1.0 (released 2013-12-05)

* No longer necessary to inject the authorisation server into a grant, the server will inject itself
* Added test for 1419ba8cdcf18dd034c8db9f7de86a2594b68605

## 3.0.1 (released 2013-12-02)

* Forgot to tell TravisCI from testing PHP 5.3

## 3.0.0 (released 2013-12-02)

* Fixed spelling of Implicit grant class (Issue #84)
* Travis CI now tests for PHP 5.5
* Fixes for checking headers for resource server (Issues #79 and #)
* The word "bearer" now has a capital "B" in JSON output to match OAuth 2.0 spec
* All grants no longer remove old sessions by default
* All grants now support custom access token TTL (Issue #92)
* All methods which didn't before return a value now return `$this` to support method chaining
* Removed the build in DB providers - these will be put in their own repos to remove baggage in the main repository
* Removed support for PHP 5.3 because this library now uses traits and will use other modern PHP features going forward
* Moved some grant related functions into a trait to reduce duplicate code

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