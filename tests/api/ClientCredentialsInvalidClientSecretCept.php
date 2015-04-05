<?php
$I = new ApiTester($scenario);
$I->wantTo('get an access token using the client credentials grant, invalid client secret');
$I->sendPOST(
    'client_credentials.php/access_token',
    [
        'grant_type'    => 'client_credentials',
        'client_id'     => 'myawesomeapp',
        'client_secret' => 'foobar'
    ]
);
$I->canSeeResponseCodeIs(401);
$I->canSeeResponseIsJson();
$I->seeResponseContainsJson([
    'error'   => 'invalid_client',
    'message' => 'Client authentication failed.'
]);
