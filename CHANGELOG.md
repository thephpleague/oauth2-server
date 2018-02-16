# Changelog

## 6.0.2 (released 2017-08-03)

* An invalid refresh token that can't be decrypted now returns a HTTP 401 error instead of HTTP 400 (Issue #759)
* Removed chmod from CryptKey and add toggle to disable checking (Issue #776)
* Fixes invalid code challenge method payload key name (Issue #777)

## 6.0.1 (released 2017-07-19)

To address feedback from the security release the following change has been made:
  
* If an RSA key cannot be chmod'ed to 600 then it will now throw a E_USER_NOTICE instead of an exception.

## 6.0.0 (released 2017-07-01)

* Breaking change: The `AuthorizationServer` constructor now expects an encryption key string instead of a public key
* Remove support for HHVM
* Remove support for PHP 5.5

## 5.1.4 (released 2017-07-01)

* Fixed multiple security vulnerabilities as a result of a security audit paid for by the [Mozilla Secure Open Source Fund](https://wiki.mozilla.org/MOSS/Secure_Open_Source). All users of this library are encouraged to update as soon as possible to this version or version 6.0 or greater.
	* It is recommended on each `AuthorizationServer` instance you set the `setEncryptionKey()`. This will result in stronger encryption being used. If this method is not set messages will be sent to the defined error handling routines (using `error_log`). Please see the examples and documentation for examples.
* TravisCI now tests PHP 7.1 (Issue #671)
* Fix middleware example fatal error (Issue #682)
* Fix typo in the first README sentence (Issue #690)
* Corrected DateInterval from 1 min to 1 month (Issue #709)

## 5.1.3 (released 2016-10-12)

* Fixed WWW-Authenticate header (Issue #669)
* Increase the recommended RSA key length from 1024 to 2048 bits (Issue #668)

## 5.1.2 (released 2016-09-19)

* Fixed `finalizeScopes` call (Issue #650)

## 5.1.1 (released 2016-07-26)

* Improved test suite (Issue #614)
* Updated docblocks (Issue #616)
* Replace `array_shift` with `foreach` loop (Issue #621)
* Allow easy addition of custom fields to Bearer token response (Issue #624)
* Key file auto-generation from string (Issue #625)

## 5.1.0 (released 2016-06-28)

* Implemented RFC7636 (Issue #574)
* Unify middleware exception responses (Issue #578)
* Updated examples (Issue #589)
* Ensure state is in access denied redirect (Issue #597)
* Remove redundant `isExpired()` method from entity interfaces and traits (Issue #600)
* Added a check for unique access token constraint violation (Issue #601)
* Look at Authorization header directly for HTTP Basic auth checks (Issue #604)
* Added catch Runtime exception when parsing JWT string (Issue #605)
* Allow `paragonie/random_compat` 2.x (Issue #606)
* Added `indigophp/hash-compat` to Composer suggestions and `require-dev` for PHP 5.5 support

## 5.0.3 (released 2016-05-04)

* Fix hints in PasswordGrant (Issue #560)
* Add meaning of `Resource owner` to terminology.md (Issue #561)
* Use constant for event name instead of explicit string (Issue #563)
* Remove unused request property (Issue #564)
* Correct wrong phpdoc (Issue #569)
* Fixed typo in exception string (Issue #570)

## 5.0.2 (released 2016-04-18)

* `state` parameter is now correctly returned after implicit grant authorization
* Small code and docblock improvements

## 5.0.1 (released 2016-04-18)

* Fixes an issue (#550) whereby it was unclear whether or not to validate a client's secret during a request.

## 5.0.0 (released 2016-04-17)

Version 5 is a complete code rewrite.

* JWT support
* PSR-7 support
* Improved exception errors
* Replace all occurrences of the term "Storage" with "Repository"
* Simplify repositories
* Entities conform to interfaces and use traits
* Auth code grant updated
    * Allow support for public clients
    * Add support for #439
* Client credentials grant updated
* Password grant updated
    * Allow support for public clients
* Refresh token grant updated
* Implement Implicit grant
* Bearer token output type
* Remove MAC token output type
* Authorization server rewrite
* Resource server class moved to PSR-7 middleware
* Tests
* Much much better documentation

Changes since RC2:

* Renamed Server class to AuthorizationServer
* Added ResourceServer class
* Run unit tests again PHP 5.5.9 as it's the minimum supported version
* Enable PHPUnit 5.0 support
* Improved examples and documentation
* Make it clearer that the implicit grant doesn't support refresh tokens
* Improved refresh token validation errors
* Fixed refresh token expiry date

## 5.0.0-RC2 (released 2016-04-10)

Changes since RC1:

* Allow multiple client redirect URIs (Issue #511)
* Remove unused mac token interface (Issue #503)
* Handle RSA key passphrase (Issue #502)
* Remove access token repository from response types (Issue #501)
* Remove unnecessary methods from entity interfaces (Issue #490)
* Ensure incoming JWT hasn't expired (Issue #509)
* Fix client identifier passed where user identifier is expected (Issue #498)
* Removed built-in entities; added traits to for quick re-use (Issue #504)
* Redirect uri is required only if the "redirect_uri" parameter was included in the authorization request (Issue #514)
* Removed templating for auth code and implicit grants (Issue #499)

## 5.0.0-RC1 (release 2016-03-24)

Version 5 is a complete code rewrite.

* JWT support
* PSR-7 support
* Improved exception errors
* Replace all occurrences of the term "Storage" with "Repository"
* Simplify repositories
* Entities conform to interfaces and use traits
* Auth code grant updated
    * Allow support for public clients
    * Add support for #439
* Client credentials grant updated
* Password grant updated
    * Allow support for public clients
* Refresh token grant updated
* Implement Implicit grant
* Bearer token output type
* Remove MAC token output type
* Authorization server rewrite
* Resource server class moved to PSR-7 middleware
* Tests
* Much much better documentation

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
* Individual grants can have custom expire times for access tokens
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