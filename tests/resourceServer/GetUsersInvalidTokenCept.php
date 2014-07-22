<?php
$I = new ResourceServerTester($scenario);
$I->wantTo('get all users with an invalid access token');
$I->sendGET('api.php/users?access_token=foobar');
$I->seeResponseCodeIs(401);
$I->seeResponseIsJson();
