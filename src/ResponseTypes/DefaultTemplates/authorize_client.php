<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Authorize <?=$this->e($client->getName())?></title>
</head>

<body>

<h1>
    Authorize <?=$this->e($client->getName())?>
</h1>

<p>
    Do you want to authorize <?=$this->e($client->getName())?> to access the following data?
</p>

<ul>
    <?php foreach ($scopes as $scope): ?>
        <li><?=$scope->getIdentifier()?></li>
    <?php endforeach; ?>
</ul>

<form method="POST">
    <input type="hidden" value="approve" name="action">
    <button type="submit">Approve</button>
</form>

<form method="POST">
    <input type="hidden" value="deny" name="action">
    <button type="submit">Deny</button>
</form>

</body>
</html>