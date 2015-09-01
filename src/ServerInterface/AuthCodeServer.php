<?php

namespace League\OAuth2\Server\ServerInterface;

interface AuthCodeServer
{
    /**
     * Require the "state" parameter in checkAuthoriseParams()
     *
     * @return bool
     */
    public function stateParamRequired();

    /**
     * Require the "state" parameter in checkAuthoriseParams()
     *
     * @param boolean $require
     *
     * @return self
     */
    public function requireStateParam($require);
}