<?php
/**
 * @author Matt Robinson <matt@inanimatt.com>
 */
namespace League\OAuth2\Server\Storage\DBAL;

use League\OAuth2\Server\Storage\ClientInterface;

class Client implements ClientInterface
{
    protected $db;

    public function __construct($db)
    {
        $this->db = $db;
    }

    public function getClient($clientId, $clientSecret = null, $redirectUri = null, $grantType = null)
    {
        if ( ! is_null($redirectUri) && is_null($clientSecret)) {
            $stmt = $this->db->prepare('SELECT oauth_clients.id, oauth_clients.secret, oauth_client_endpoints.redirect_uri, oauth_clients.name FROM oauth_clients LEFT JOIN oauth_client_endpoints ON oauth_client_endpoints.client_id = oauth_clients.id WHERE oauth_clients.id = :clientId AND oauth_client_endpoints.redirect_uri = :redirectUri');
            $stmt->bindValue(':redirectUri', $redirectUri);
        }

        elseif ( ! is_null($clientSecret) && is_null($redirectUri)) {
            $stmt = $this->db->prepare('SELECT oauth_clients.id, oauth_clients.secret, oauth_clients.name FROM oauth_clients  WHERE oauth_clients.id = :clientId AND oauth_clients.secret = :clientSecret');
            $stmt->bindValue(':clientSecret', $clientSecret);
        }

        elseif ( ! is_null($clientSecret) && ! is_null($redirectUri)) {
            $stmt = $this->db->prepare('SELECT oauth_clients.id, oauth_clients.secret, oauth_client_endpoints.redirect_uri, oauth_clients.name FROM oauth_clients LEFT JOIN oauth_client_endpoints ON oauth_client_endpoints.client_id = oauth_clients.id WHERE oauth_clients.id = :clientId AND oauth_clients.secret = :clientSecret AND oauth_client_endpoints.redirect_uri = :redirectUri');
            $stmt->bindValue(':redirectUri', $redirectUri);
            $stmt->bindValue(':clientSecret', $clientSecret);
        }

        $stmt->bindValue(':clientId', $clientId);
        $stmt->execute();

        $row = $stmt->fetch(\PDO::FETCH_OBJ);

        if ($row === false) {
            return false;
        }

        return array(
            'client_id' =>  $row->id,
            'client_secret' =>  $row->secret,
            'redirect_uri'  =>  (isset($row->redirect_uri)) ? $row->redirect_uri : null,
            'name'  =>  $row->name
        );
    }
}