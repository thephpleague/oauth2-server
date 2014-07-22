<?php
$I = new ResourceServerTester($scenario);
$I->wantTo('get all users with basic and photo fields');
$I->sendGET('api.php/users?access_token=iamalex');
$I->seeResponseCodeIs(200);
$I->seeResponseIsJson();
$I->seeResponseContainsJson([
    [
        'username'  =>  'alexbilbie',
        'name'      =>  'Alex Bilbie',
        'photo'     =>  'https://s.gravatar.com/avatar/14902eb1dac66b8458ebbb481d80f0a3'
    ],
    [
        'username'  =>  'philsturgeon',
        'name'      =>  'Phil Sturgeon',
        'photo'     =>  'https://s.gravatar.com/avatar/14df293d6c5cd6f05996dfc606a6a951'
    ]
]);
