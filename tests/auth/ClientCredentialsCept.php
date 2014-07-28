<?php
$I = new AuthTester($scenario);
$I->wantTo('get an access token with client credentials');
$I->sendPOST('other_grants.php/access_token', [
    'client_id'     => 'testclient',
    'client_secret' => 'secret',
    'grant_type'    => 'client_credentials'
]);
$I->seeResponseCodeIs(200);
$I->seeResponseIsJson();
$I->seeJsonKeyExists('expires_in');
$I->seeJsonKeyExists('access_token');
$I->seeResponseContainsJson(['token_type' => 'Bearer']);
$I->seeJsonKeyDoesNotExists('foobar');