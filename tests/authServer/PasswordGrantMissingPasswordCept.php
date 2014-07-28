<?php
$I = new AuthTester($scenario);
$I->wantTo('get an access token with resource owner credentials');
$I->sendPOST('other_grants.php/access_token', [
    'client_id'     => 'testclient',
    'client_secret' => 'secret',
    'grant_type'    => 'password',
    'username'      => 'alexbilbie'
]);
$I->seeResponseCodeIs(400);
$I->seeResponseIsJson();