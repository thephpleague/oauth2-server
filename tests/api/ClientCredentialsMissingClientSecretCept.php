<?php
$I = new ApiTester($scenario);
$I->wantTo('get an access token using the client credentials grant, missing client secret');
$I->sendPOST(
    'client_credentials.php/access_token',
    [
        'grant_type' => 'client_credentials',
        'client_id'  => 'myawesomeapp'
    ]
);
$I->canSeeResponseCodeIs(400);
$I->canSeeResponseIsJson();
$I->seeResponseContainsJson([
    'error'   => 'invalid_request',
    'message' => 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "client_secret" parameter.'
]);
