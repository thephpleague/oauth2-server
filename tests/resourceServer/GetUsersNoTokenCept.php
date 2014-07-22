<?php
$I = new ResourceServerTester($scenario);
$I->wantTo('get all users without an access token');
$I->sendGET('api.php/users');
$I->seeResponseCodeIs(400);
$I->seeResponseIsJson();
