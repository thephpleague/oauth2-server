# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Clients are now explicitly prevented from using the Client Credentials grant unless they are confidential to conform
 with the OAuth2 spec (PR #1035)

## [8.0.0] - released 2019-07-13

### Added
- Flag, `requireCodeChallengeForPublicClients`, used to reject public clients that do not provide a code challenge for the Auth Code Grant; use AuthCodeGrant::disableRequireCodeCallengeForPublicClients() to turn off this requirement (PR #938)
- Public clients can now use the Auth Code Grant (PR #938)
- `isConfidential` getter added to `ClientEntity` to identify type of client (PR #938)
- Function `validateClient()` added to validate clients which was previously performed by the `getClientEntity()` function (PR #938)
- Add a new function to the AbstractGrant class called `getClientEntityOrFail()`. This is a wrapper around the `getClientEntity()` function that ensures we emit and throw an exception if the repo doesn't return a client entity. (PR #1010)

### Changed
- Replace `convertToJWT()` interface with a more generic `__toString()` to improve extensibility; AccessTokenEntityInterface now requires `setPrivateKey(CryptKey $privateKey)` so `__toString()` has everything it needs to work (PR #874)
- The `invalidClient()` function accepts a PSR-7 compliant `$serverRequest` argument to avoid accessing the `$_SERVER` global variable and improve testing (PR #899)
- `issueAccessToken()` in the Abstract Grant no longer sets access token client, user ID or scopes. These values should already have been set when calling `getNewToken()` (PR #919)
- No longer need to enable PKCE with `enableCodeExchangeProof` flag. Any client sending a code challenge will initiate PKCE checks. (PR #938)
- Function `getClientEntity()` no longer performs client validation (PR #938)
- Password Grant now returns an invalid_grant error instead of invalid_credentials if a user cannot be validated (PR #967)
- Use `DateTimeImmutable()` instead of `DateTime()`, `time()` instead of `(new DateTime())->getTimeStamp()`, and `DateTime::getTimeStamp()` instead of `DateTime::format('U')` (PR #963)

### Removed
- `enableCodeExchangeProof` flag (PR #938)
- Support for PHP 7.0 (PR #1014)
- Remove JTI claim from JWT header (PR #1031)

## [7.4.0] - released 2019-05-05

### Changed
- RefreshTokenRepository can now return null, allowing refresh tokens to be optional. (PR #649)

## [7.3.3] - released 2019-03-29

### Added
- Added `error_description` to the error payload to improve standards compliance. The contents of this are copied from the existing `message` value. (PR #1006)

### Deprecated
- Error payload will not issue `message` value in the next major release (PR #1006)

## [7.3.2] - released 2018-11-21

### Fixed
- Revert setting keys on response type to be inside `getResponseType()` function instead of AuthorizationServer constructor (PR #969)

## [7.3.1] - released 2018-11-15

### Fixed
- Fix issue with previous release where interface had changed for the AuthorizationServer. Reverted to the previous interface while maintaining functionality changes (PR #970)

## [7.3.0] - released 2018-11-13

### Changed
- Moved  the `finalizeScopes()` call from `validateAuthorizationRequest` method to the `completeAuthorizationRequest` method so it is called just before the access token is issued (PR #923)

### Added
- Added a ScopeTrait to provide an implementation for jsonSerialize (PR #952)
- Ability to nest exceptions (PR #965)

### Fixed
- Fix issue where AuthorizationServer is not stateless as ResponseType could store state of a previous request (PR #960)

## [7.2.0] - released 2018-06-23

### Changed
- Added new`validateRedirectUri` method AbstractGrant to remove three instances of code duplication (PR #912)
- Allow 640 as a crypt key file permission (PR #917)

### Added
- Function `hasRedirect()` added to `OAuthServerException` (PR #703)

### Fixed
- Catch and handle `BadMethodCallException` from the `verify()` method of the JWT token in the `validateAuthorization` method (PR #904)

## [4.1.7] - released 2018-06-23

### Fixed
- Ensure `empty()` function call only contains variable to be compatible with PHP 5.4 (PR #918)

## [7.1.1] - released 2018-05-21

### Fixed
- No longer set a WWW-Authenticate header for invalid clients if the client did not send an Authorization header in the original request (PR #902)

## [7.1.0] - released 2018-04-22

### Changed
- Changed hint for unsupportedGrantType exception so it no longer references the grant type parameter which isn't always expected (PR #893)
- Upgrade PHPStan checks to level 7 (PR #856)

### Added
- Added event emitters for issued access and refresh tokens (PR #860)
- Can now use Defuse\Crypto\Key for encryption/decryption of keys which is faster than the Cryto class (PR #812)

### Removed
- Remove paragone/random_compat from dependencies

## [7.0.0] - released 2018-02-18

### Added
- Use PHPStan for static analysis of code (PR #848)
- Enforce stricter static analysis checks and upgrade library dependencies (PR #852)
- Provide PHPStan coverage for tests and update PHPUnit (PR #849)
- Get and set methods for OAuth Server Exception payloads. Allow implementer to specify the JSON encode options (PR #719)

### Changed
- ClientRepository interface will now accept null for the Grant type to improve extensibility options (PR #607)
- Do not issue an error if key file permissions are 400 or 440 (PR #839)
- Skip key file creation if the file already exists (PR #845)
- Change changelog format and update readme

### Removed
- Support for PHP 5.6
- Support for version 5.x and 6.x of the library

### Fixed
- PKCE implementation (PR #744)
- Set correct redirect URI when validating scopes (PR #840)
- S256 code challenege method (PR #842)
- Accept RSA key with CRLF line endings (PR #805)

## [6.1.1] - 2017-12-23

- Removed check on empty scopes

## [6.1.0] - 2017-12-23

- Changed the token type issued by the Implicit Grant to be Bearer instead of bearer. (PR #724)
- Replaced call to array_key_exists() with the faster isset() on the Implicit Grant. (PR #749)
- Allow specification of query delimiter character in the Password Grant (PR #801)
- Add Zend Diactoros library dependency to examples (PR #678)
- Can set default scope for the authorization endpoint. If no scope is passed during an authorization request, the default scope will be used if set. If not, the server will issue an invalid scope exception (PR #811)
- Added validation for redirect URIs on the authorization end point to ensure exactly one redirection URI has been passed (PR #573)

## [6.0.2] - 2017-08-03

- An invalid refresh token that can't be decrypted now returns a HTTP 401 error instead of HTTP 400 (Issue #759)
- Removed chmod from CryptKey and add toggle to disable checking (Issue #776)
- Fixes invalid code challenge method payload key name (Issue #777)

## [6.0.1] - 2017-07-19

To address feedback from the security release the following change has been made:

- If an RSA key cannot be chmod'ed to 600 then it will now throw a E_USER_NOTICE instead of an exception.

## [6.0.0] - 2017-07-01

- Breaking change: The `AuthorizationServer` constructor now expects an encryption key string instead of a public key
- Remove support for HHVM
- Remove support for PHP 5.5

## [5.1.4] - 2017-07-01

- Fixed multiple security vulnerabilities as a result of a security audit paid for by the [Mozilla Secure Open Source Fund](https://wiki.mozilla.org/MOSS/Secure_Open_Source). All users of this library are encouraged to update as soon as possible to this version or version 6.0 or greater.
	- It is recommended on each `AuthorizationServer` instance you set the `setEncryptionKey()`. This will result in stronger encryption being used. If this method is not set messages will be sent to the defined error handling routines (using `error_log`). Please see the examples and documentation for examples.
- TravisCI now tests PHP 7.1 (Issue #671)
- Fix middleware example fatal error (Issue #682)
- Fix typo in the first README sentence (Issue #690)
- Corrected DateInterval from 1 min to 1 month (Issue #709)

## [5.1.3] - 2016-10-12

- Fixed WWW-Authenticate header (Issue #669)
- Increase the recommended RSA key length from 1024 to 2048 bits (Issue #668)

## [5.1.2] - 2016-09-19

- Fixed `finalizeScopes` call (Issue #650)

## [4.1.6] - 2016-09-13

- Less restrictive on Authorization header check (Issue #652)

## [5.1.1] - 2016-07-26

- Improved test suite (Issue #614)
- Updated docblocks (Issue #616)
- Replace `array_shift` with `foreach` loop (Issue #621)
- Allow easy addition of custom fields to Bearer token response (Issue #624)
- Key file auto-generation from string (Issue #625)

## [5.1.0] - 2016-06-28

- Implemented RFC7636 (Issue #574)
- Unify middleware exception responses (Issue #578)
- Updated examples (Issue #589)
- Ensure state is in access denied redirect (Issue #597)
- Remove redundant `isExpired()` method from entity interfaces and traits (Issue #600)
- Added a check for unique access token constraint violation (Issue #601)
- Look at Authorization header directly for HTTP Basic auth checks (Issue #604)
- Added catch Runtime exception when parsing JWT string (Issue #605)
- Allow `paragonie/random_compat` 2.x (Issue #606)
- Added `indigophp/hash-compat` to Composer suggestions and `require-dev` for PHP 5.5 support

## [5.0.3] - 2016-05-04

- Fix hints in PasswordGrant (Issue #560)
- Add meaning of `Resource owner` to terminology.md (Issue #561)
- Use constant for event name instead of explicit string (Issue #563)
- Remove unused request property (Issue #564)
- Correct wrong phpdoc (Issue #569)
- Fixed typo in exception string (Issue #570)

## [5.0.2] - 2016-04-18

- `state` parameter is now correctly returned after implicit grant authorization
- Small code and docblock improvements

## [5.0.1] - 2016-04-18

- Fixes an issue (#550) whereby it was unclear whether or not to validate a client's secret during a request.

## [5.0.0] - 2016-04-17

Version 5 is a complete code rewrite.

- Renamed Server class to AuthorizationServer
- Added ResourceServer class
- Run unit tests again PHP 5.5.9 as it's the minimum supported version
- Enable PHPUnit 5.0 support
- Improved examples and documentation
- Make it clearer that the implicit grant doesn't support refresh tokens
- Improved refresh token validation errors
- Fixed refresh token expiry date

## [5.0.0-RC2] - 2016-04-10

- Allow multiple client redirect URIs (Issue #511)
- Remove unused mac token interface (Issue #503)
- Handle RSA key passphrase (Issue #502)
- Remove access token repository from response types (Issue #501)
- Remove unnecessary methods from entity interfaces (Issue #490)
- Ensure incoming JWT hasn't expired (Issue #509)
- Fix client identifier passed where user identifier is expected (Issue #498)
- Removed built-in entities; added traits to for quick re-use (Issue #504)
- Redirect uri is required only if the "redirect_uri" parameter was included in the authorization request (Issue #514)
- Removed templating for auth code and implicit grants (Issue #499)

## [5.0.0-RC1] - 2016-03-24

Version 5 is a complete code rewrite.

- JWT support
- PSR-7 support
- Improved exception errors
- Replace all occurrences of the term "Storage" with "Repository"
- Simplify repositories
- Entities conform to interfaces and use traits
- Auth code grant updated
  - Allow support for public clients
  - Add support for #439
- Client credentials grant updated
- Password grant updated
  - Allow support for public clients
- Refresh token grant updated
- Implement Implicit grant
- Bearer token output type
- Remove MAC token output type
- Authorization server rewrite
- Resource server class moved to PSR-7 middleware
- Tests
- Much much better documentation

## [4.1.5] - 2016-01-04

- Enable Symfony 3.0 support (#412)

## [4.1.4] - 2015-11-13

- Fix for determining access token in header (Issue #328)
- Refresh tokens are now returned for MAC responses (Issue #356)
- Added integration list to readme (Issue #341)
- Expose parameter passed to exceptions (Issue #345)
- Removed duplicate routing setup code (Issue #346)
- Docs fix (Issues #347, #360, #380)
- Examples fix (Issues #348, #358)
- Fix typo in docblock (Issue #352)
- Improved timeouts for MAC tokens (Issue #364)
- `hash_hmac()` should output raw binary data, not hexits (Issue #370)
- Improved regex for matching all Base64 characters (Issue #371)
- Fix incorrect signature parameter (Issue #372)
- AuthCodeGrant and RefreshTokenGrant don't require client_secret (Issue #377)
- Added priority argument to event listener (Issue #388)

## [4.1.3] - 2015-03-22

- Docblock, namespace and inconsistency fixes (Issue #303)
- Docblock type fix (Issue #310)
- Example bug fix (Issue #300)
- Updated league/event to ~2.1 (Issue #311)
- Fixed missing session scope (Issue #319)
- Updated interface docs (Issue #323)
- `.travis.yml` updates

## [4.1.2] - 2015-01-01

- Remove side-effects in hash_equals() implementation (Issue #290)

## [4.1.1] - 2014-12-31

- Changed `symfony/http-foundation` dependency version to `~2.4` so package can be installed in Laravel `4.1.*`

## [4.1.0] - 2014-12-27

- Added MAC token support (Issue #158)
- Fixed example init code (Issue #280)
- Toggle refresh token rotation (Issue #286)
- Docblock fixes

## [4.0.5] - 2014-12-15

- Prevent duplicate session in auth code grant (Issue #282)

## [4.0.4] - 2014-12-03

- Ensure refresh token hasn't expired (Issue #270)

## [4.0.3] - 2014-12-02

- Fix bad type hintings (Issue #267)
- Do not forget to set the expire time (Issue #268)

## [4.0.2] - 2014-11-21

- Improved interfaces (Issue #255)
- Learnt how to spell delimiter and so `getScopeDelimiter()` and `setScopeDelimiter()` methods have been renamed
- Docblock improvements (Issue #254)

## [4.0.1] - 2014-11-09

- Alias the master branch in composer.json (Issue #243)
- Numerous PHP CodeSniffer fixes (Issue #244)
- .travis.yml update (Issue #245)
- The getAccessToken method should return an AccessTokenEntity object instead of a string in ResourceServer.php (#246)

## [4.0.0] - 2014-11-08

- Complete rewrite
- Check out the documentation - [http://oauth2.thephpleague.com](http://oauth2.thephpleague.com)

## [3.2.0] - 2014-04-16

- Added the ability to change the algorithm that is used to generate the token strings (Issue #151)

## [3.1.2] - 2014-02-26

- Support Authorization being an environment variable. [See more](http://fortrabbit.com/docs/essentials/quirks-and-constraints#authorization-header)

## [3.1.1] - 2013-12-05

- Normalize headers when `getallheaders()` is available (Issues #108 and #114)

## [3.1.0] - 2013-12-05

- No longer necessary to inject the authorisation server into a grant, the server will inject itself
- Added test for 1419ba8cdcf18dd034c8db9f7de86a2594b68605

## [3.0.1] - 2013-12-02

- Forgot to tell TravisCI from testing PHP 5.3

## [3.0.0] - 2013-12-02

- Fixed spelling of Implicit grant class (Issue #84)
- Travis CI now tests for PHP 5.5
- Fixes for checking headers for resource server (Issues #79 and #)
- The word "bearer" now has a capital "B" in JSON output to match OAuth 2.0 spec
- All grants no longer remove old sessions by default
- All grants now support custom access token TTL (Issue #92)
- All methods which didn't before return a value now return `$this` to support method chaining
- Removed the build in DB providers - these will be put in their own repos to remove baggage in the main repository
- Removed support for PHP 5.3 because this library now uses traits and will use other modern PHP features going forward
- Moved some grant related functions into a trait to reduce duplicate code

## [2.1.1] - 2013-06-02

- Added conditional `isValid()` flag to check for Authorization header only (thanks @alexmcroberts)
- Fixed semantic meaning of `requireScopeParam()` and `requireStateParam()` by changing their default value to true
- Updated some duff docblocks
- Corrected array key call in Resource.php (Issue #63)

## [2.1.0] - 2013-05-10

- Moved zetacomponents/database to "suggest" in composer.json. If you rely on this feature you now need to include " zetacomponents/database" into "require" key in your own composer.json. (Issue #51)
- New method in Refresh grant called `rotateRefreshTokens()`. Pass in `true` to issue a new refresh token each time an access token is refreshed. This parameter needs to be set to true in order to request reduced scopes with the new access token. (Issue #47)
- Rename `key` column in oauth_scopes table to `scope` as `key` is a reserved SQL word. (Issue #45)
- The `scope` parameter is no longer required by default as per the RFC. (Issue #43)
- You can now set multiple default scopes by passing an array into `setDefaultScope()`. (Issue #42)
- The password and client credentials grants now allow for multiple sessions per user. (Issue #32)
- Scopes associated to authorization codes are not held in their own table (Issue #44)
- Database schema updates.

## [2.0.5] - 2013-05-09

- Fixed `oauth_session_token_scopes` table primary key
- Removed `DEFAULT ''` that has slipped into some tables
- Fixed docblock for `SessionInterface::associateRefreshToken()`

## [2.0.4] - 2013-05-09

- Renamed primary key in oauth_client_endpoints table
- Adding missing column to oauth_session_authcodes

### Security
- A refresh token should be bound to a client ID

## [2.0.3] - 2013-05-08

- Fixed a link to code in composer.json

## [2.0.2] - 2013-05-08

- Updated README with wiki guides
- Removed `null` as default parameters in some methods in the storage interfaces
- Fixed license copyright

## [2.0.0] - 2013-05-08

**If you're upgrading from v1.0.8 there are lots of breaking changes**

- Rewrote the session storage interface from scratch so methods are more obvious
- Included a PDO driver which implements the storage interfaces so the library is more "get up and go"
- Further normalised the database structure so all sessions no longer contain infomation related to authorization grant (which may or may not be enabled)
- A session can have multiple associated access tokens
- Individual grants can have custom expire times for access tokens
- Authorization codes now have a TTL of 10 minutes by default (can be manually set)
- Refresh tokens now have a TTL of one week by default (can be manually set)
- The client credentials grant will no longer gives out refresh tokens as per the specification

## [1.0.8] - 2013-03-18

- Fixed check for required state parameter
- Fixed check that user's credentials are correct in Password grant

## [1.0.7] - 2013-03-04

- Added method `requireStateParam()`
- Added method `requireScopeParam()`

## [1.0.6] - 2013-02-22

- Added links to tutorials in the README
- Added missing `state` parameter request to the `checkAuthoriseParams()` method.

## [1.0.5] - 2013-02-21

- Fixed the SQL example for SessionInterface::getScopes()

## [1.0.3] - 2013-02-20

- Changed all instances of the "authentication server" to "authorization server"

## [1.0.2] - 2013-02-20

- Fixed MySQL create table order
- Fixed version number in composer.json

## [1.0.1] - 2013-02-19

- Updated AuthServer.php to use `self::getParam()`

## 1.0.0 - 2013-02-15

- First major release

[Unreleased]: https://github.com/thephpleague/oauth2-server/compare/8.0.0...HEAD
[8.0.0]: https://github.com/thephpleague/oauth2-server/compare/7.4.0...8.0.0
[7.4.0]: https://github.com/thephpleague/oauth2-server/compare/7.3.3...7.4.0
[7.3.3]: https://github.com/thephpleague/oauth2-server/compare/7.3.2...7.3.3
[7.3.2]: https://github.com/thephpleague/oauth2-server/compare/7.3.1...7.3.2
[7.3.1]: https://github.com/thephpleague/oauth2-server/compare/7.3.0...7.3.1
[7.3.0]: https://github.com/thephpleague/oauth2-server/compare/7.2.0...7.3.0
[7.2.0]: https://github.com/thephpleague/oauth2-server/compare/7.1.1...7.2.0
[7.1.1]: https://github.com/thephpleague/oauth2-server/compare/7.1.0...7.1.1
[7.1.0]: https://github.com/thephpleague/oauth2-server/compare/7.0.0...7.1.0
[7.0.0]: https://github.com/thephpleague/oauth2-server/compare/6.1.1...7.0.0
[6.1.1]: https://github.com/thephpleague/oauth2-server/compare/6.0.0...6.1.1
[6.1.0]: https://github.com/thephpleague/oauth2-server/compare/6.0.2...6.1.0
[6.0.2]: https://github.com/thephpleague/oauth2-server/compare/6.0.1...6.0.2
[6.0.1]: https://github.com/thephpleague/oauth2-server/compare/6.0.0...6.0.1
[6.0.0]: https://github.com/thephpleague/oauth2-server/compare/5.1.4...6.0.0
[5.1.4]: https://github.com/thephpleague/oauth2-server/compare/5.1.3...5.1.4
[5.1.3]: https://github.com/thephpleague/oauth2-server/compare/5.1.2...5.1.3
[5.1.2]: https://github.com/thephpleague/oauth2-server/compare/5.1.1...5.1.2
[5.1.1]: https://github.com/thephpleague/oauth2-server/compare/5.1.0...5.1.1
[5.1.0]: https://github.com/thephpleague/oauth2-server/compare/5.0.2...5.1.0
[5.0.3]: https://github.com/thephpleague/oauth2-server/compare/5.0.3...5.0.2
[5.0.2]: https://github.com/thephpleague/oauth2-server/compare/5.0.1...5.0.2
[5.0.1]: https://github.com/thephpleague/oauth2-server/compare/5.0.0...5.0.1
[5.0.0]: https://github.com/thephpleague/oauth2-server/compare/5.0.0-RC2...5.0.0
[5.0.0-RC2]: https://github.com/thephpleague/oauth2-server/compare/5.0.0-RC1...5.0.0-RC2
[5.0.0-RC1]: https://github.com/thephpleague/oauth2-server/compare/4.1.5...5.0.0-RC1
[4.1.7]: https://github.com/thephpleague/oauth2-server/compare/4.1.6...4.1.7
[4.1.6]: https://github.com/thephpleague/oauth2-server/compare/4.1.5...4.1.6
[4.1.5]: https://github.com/thephpleague/oauth2-server/compare/4.1.4...4.1.5
[4.1.4]: https://github.com/thephpleague/oauth2-server/compare/4.1.3...4.1.4
[4.1.3]: https://github.com/thephpleague/oauth2-server/compare/4.1.2...4.1.3
[4.1.2]: https://github.com/thephpleague/oauth2-server/compare/4.1.1...4.1.2
[4.1.1]: https://github.com/thephpleague/oauth2-server/compare/4.0.0...4.1.1
[4.1.0]: https://github.com/thephpleague/oauth2-server/compare/4.0.5...4.1.0
[4.0.5]: https://github.com/thephpleague/oauth2-server/compare/4.0.4...4.0.5
[4.0.4]: https://github.com/thephpleague/oauth2-server/compare/4.0.3...4.0.4
[4.0.3]: https://github.com/thephpleague/oauth2-server/compare/4.0.2...4.0.3
[4.0.2]: https://github.com/thephpleague/oauth2-server/compare/4.0.1...4.0.2
[4.0.1]: https://github.com/thephpleague/oauth2-server/compare/4.0.0...4.0.1
[4.0.0]: https://github.com/thephpleague/oauth2-server/compare/3.2.0...4.0.0
[3.2.0]: https://github.com/thephpleague/oauth2-server/compare/3.1.2...3.2.0
[3.1.2]: https://github.com/thephpleague/oauth2-server/compare/3.1.1...3.1.2
[3.1.1]: https://github.com/thephpleague/oauth2-server/compare/3.1.0...3.1.1
[3.1.0]: https://github.com/thephpleague/oauth2-server/compare/3.0.1...3.1.0
[3.0.1]: https://github.com/thephpleague/oauth2-server/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/thephpleague/oauth2-server/compare/2.1.1...3.0.0
[2.1.1]: https://github.com/thephpleague/oauth2-server/compare/2.1.0...2.1.1
[2.1.0]: https://github.com/thephpleague/oauth2-server/compare/2.0.5...2.1.0
[2.0.5]: https://github.com/thephpleague/oauth2-server/compare/2.0.4...2.0.5
[2.0.4]: https://github.com/thephpleague/oauth2-server/compare/2.0.3...2.0.4
[2.0.3]: https://github.com/thephpleague/oauth2-server/compare/2.0.2...2.0.3
[2.0.2]: https://github.com/thephpleague/oauth2-server/compare/2.0.0...2.0.2
[2.0.0]: https://github.com/thephpleague/oauth2-server/compare/1.0.8...2.0.0
[1.0.8]: https://github.com/thephpleague/oauth2-server/compare/1.0.7...1.0.8
[1.0.7]: https://github.com/thephpleague/oauth2-server/compare/1.0.6...1.0.7
[1.0.6]: https://github.com/thephpleague/oauth2-server/compare/1.0.5...1.0.6
[1.0.5]: https://github.com/thephpleague/oauth2-server/compare/1.0.3...1.0.5
[1.0.3]: https://github.com/thephpleague/oauth2-server/compare/1.0.2...1.0.3
[1.0.2]: https://github.com/thephpleague/oauth2-server/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/thephpleague/oauth2-server/compare/1.0.0...1.0.1
