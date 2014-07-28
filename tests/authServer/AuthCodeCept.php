<?php
$I = new AuthTester($scenario);
$I->wantTo('get an access token with an authorization code');
$I->sendGET('authcode_grant.php/authorize?client_id=testclient&redirect_uri=http%3A%2F%2Fexample.com%2Fredirect&response_type=code&scope=basic');
$I->seeResponseCodeIs(200);
$I->seeHttpHeader('Location');

$location = $I->grabHttpHeader('Location');
$urlParts = parse_url($location);
parse_str($urlParts['query'], $queryString);

$I->sendPOST('authcode_grant.php/access_token', [
    'client_id'     => 'testclient',
    'redirect_uri'  => 'http://example.com/redirect',
    'client_secret' => 'secret',
    'code'          => $queryString['code'],
    'grant_type'    => 'authorization_code'
]);
$I->seeResponseCodeIs(200);
$I->seeResponseIsJson();
$I->seeJsonKeyExists('expires_in');
$I->seeJsonKeyExists('access_token');
$I->seeResponseContainsJson(['token_type' => 'Bearer']);
$I->seeJsonKeyDoesNotExists('foobar');