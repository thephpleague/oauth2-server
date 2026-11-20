<?php

namespace League\OAuth2\Server\TokenExchange;

/**
 * Defines the token types mentioned in RFC 8693 section 3.
 *
 * Other values MAY be used as token types.
 */
class TokenType {
	/** This token type means an access token issued by this server. */
	public const ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

	/** This token type means a refresh token issued by this server */
	public const REFRESH_TOKEN = 'urn:ietf:params:oauth:token-type:refresh_token';

	/** This token type means an ID token as used in OpenID Connect. */
	public const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';

	/** This token type means a base64-encoded SAML 1.1 assertion */
	public const SAML1 = 'urn:ietf:params:oauth:token-type:saml1';

	/** This token type means a base64-encoded SAML 2.0 assertion */
	public const SAML2 = 'urn:ietf:params:oauth:token-type:saml2';

	/** This token type means a JSON Web Token */
	public const JWT = 'urn:ietf:params:oauth:token-type:jwt';
}
