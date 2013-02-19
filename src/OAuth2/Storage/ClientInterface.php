<?php
/**
 * OAuth 2.0 Client storage interface
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2\Storage;

interface ClientInterface
{
	/**
	 * Validate a client
	 *
	 * Example SQL query:
	 *
	 * <code>
	 * # Client ID + redirect URI
	 * SELECT oauth_clients.id FROM oauth_clients LEFT JOIN client_endpoints ON client_endpoints.client_id
	 *  = oauth_clients.id WHERE oauth_clients.id = $clientId AND client_endpoints.redirect_uri = $redirectUri
	 *
	 * # Client ID + client secret
	 * SELECT oauth_clients.id FROM oauth_clients  WHERE oauth_clients.id = $clientId AND
	 *  oauth_clients.secret = $clientSecret
	 *
	 * # Client ID + client secret + redirect URI
	 * SELECT oauth_clients.id FROM oauth_clients LEFT JOIN client_endpoints ON client_endpoints.client_id
	 *  = oauth_clients.id WHERE oauth_clients.id = $clientId AND oauth_clients.secret = $clientSecret
	 *  AND client_endpoints.redirect_uri = $redirectUri
	 * </code>
	 *
	 * Response:
	 *
	 * <code>
	 * Array
	 * (
	 *     [client_id] => (string) The client ID
	 *     [client secret] => (string) The client secret
	 *     [redirect_uri] => (string) The redirect URI used in this request
	 *     [name] => (string) The name of the client
	 * )
	 * </code>
	 *
	 * @param  string     $clientId     The client's ID
	 * @param  string     $clientSecret The client's secret (default = "null")
	 * @param  string     $redirectUri  The client's redirect URI (default = "null")
	 * @return bool|array               Returns false if the validation fails, array on success
	 */
    public function getClient($clientId = null, $clientSecret = null, $redirectUri = null);
}