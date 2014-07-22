<?php
$I = new ApiTester($scenario);
$I->wantTo('get all users with all basic and email fields');
$I->sendGET('api.php/users?access_token=iamphil');
$I->seeResponseCodeIs(200);
$I->seeResponseIsJson();
$I->seeResponseContainsJson([
    [
        'username'  =>  'alexbilbie',
        'name'      =>  'Alex Bilbie',
        'email'     =>  'hello@alexbilbie.com'
    ],
    [
        'username'  =>  'philsturgeon',
        'name'      =>  'Phil Sturgeon',
        'email'     =>  'email@philsturgeon.co.uk'
    ]
]);
