<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Login</title>
</head>

<body>

    <h1>Login</h1>

    <?php if ($error !== null): ?>
    <div style="border:solid 1px red; padding: 1rem; margin-bottom:1rem">
        <?=$this->e($error)?>
    </div>
    <?php endif; ?>

    <form method="POST">

        <label for="username">Username</label>
        <input type="text" id="username" name="username">

        <br>

        <label for="password">Password</label>
        <input type="password" id="password" name="password">

        <br>

        <input type="submit" value="Login">

    </form>

</body>
</html>