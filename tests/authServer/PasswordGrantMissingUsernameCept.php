<?php
$I = new AuthTester($scenario);
$I->wantTo('get an access token with resource owner credentials');
$I->sendPOST('other_grants.php/access_token', [
    'client_id'     => 'testclient',
    'client_secret' => 'secret',
    'grant_type'    => 'password'
]);
$I->seeResponseCodeIs(400);
$I->seeResponseIsJson();
$I->seeResponseContainsJson([
    'error' => 'invalid_request',
    'message' => 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter
                 more than once, or is otherwise malformed. Check the "username" parameter.'
]);