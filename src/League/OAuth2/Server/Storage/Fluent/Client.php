<?php

namespace League\OAuth2\Server\Storage\Fluent;

use \Illuminate\Support\Facades\DB as DB;
use \League\OAuth2\Server\Storage\ClientInterface;

class Client implements ClientInterface {

    public function getClient($clientId, $clientSecret = null, $redirectUri = null, $grantType) {
        if (!is_null($redirectUri) && is_null($clientSecret)) {
            $result = DB::table('oauth_clients')
                    ->join('oauth_client_endpoints', 'oauth_clients.id', '=', 'oauth_client_endpoints.client_id')
                    ->where('oauth_clients.id', $clientId)
                    ->where('oauth_client_endpoints.redirect_uri', $redirectUri)
                    ->first();
        } elseif (!is_null($clientSecret) && is_null($redirectUri)) {
            $result = DB::table('oauth_clients')
                    ->where('id', $clientId)
                    ->where('secret', $clientSecret)
                    ->first();
        } elseif (!is_null($clientSecret) && !is_null($redirectUri)) {
            $result = DB::table('oauth_clients')
                    ->join('oauth_client_endpoints', 'oauth_clients.id', '=', 'oauth_client_endpoints.client_id')
                    ->where('oauth_clients.id', $clientId)
                    ->where('oauth_clients.secret', $clientSecret)
                    ->where('oauth_client_endpoints.redirect_uri', $redirectUri)
                    ->first();
        }

        if (is_null($result)) {
            return false;
        }

        return array(
            'client_id'     => $result->id,
            'client_secret' => $result->secret,
            'redirect_uri'  => (isset($result->redirect_uri)) ? $result->redirect_uri : null,
            'name'          => $result->name,
            'auto_approve'  => $result->auto_approve
        );
    }

}