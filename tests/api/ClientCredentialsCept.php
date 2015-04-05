<?php
$I = new ApiTester($scenario);
$I->wantTo('get an access token using the client credentials grant');
$I->sendPOST(
    'access_token',
    [
        'grant_type'    => 'client_credentials',
        'client_id'     => 'myawesomeapp',
        'client_secret' => 'abc123',
        'scope'         => 'basic'
    ]
);
$I->canSeeResponseCodeIs(200);
$I->canSeeResponseIsJson();
$I->seeResponseJsonMatchesJsonPath('$.token_type');
$I->seeResponseJsonMatchesJsonPath('$.expires_in');
$I->seeResponseJsonMatchesJsonPath('$.access_token');