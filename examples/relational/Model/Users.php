<?php

namespace RelationalExample\Model;

use Illuminate\Database\Capsule\Manager as Capsule;

class Users
{
    public function get($username = null)
    {
        $query = Capsule::table('users')->select(['username', 'password', 'name', 'email', 'photo']);

        if ($username !== null) {
            $query->where('username', '=', $username);
        }

        $result = $query->get();

        if (count($result) > 0) {
            return $result;
        }

        return;
    }
}
