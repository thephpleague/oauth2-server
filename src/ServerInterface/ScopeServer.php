<?php

namespace League\OAuth2\Server\ServerInterface;

interface ScopeServer
{
    /**
     * Require the "scope" parameter in checkAuthoriseParams()
     *
     * @param boolean $require
     *
     * @return self
     */
    public function requireScopeParam($require);

    /**
     * Is the scope parameter required?
     *
     * @return bool
     */
    public function scopeParamRequired();


    /**
     * Default scope to be used if none is provided and requireScopeParam() is false
     *
     * @param string $default Name of the default scope
     *
     * @return self
     */
    public function setDefaultScope($default);

    /**
     * Default scope to be used if none is provided and requireScopeParam is false
     *
     * @return string|null
     */
    public function getDefaultScope();

    /**
     * Get the scope delimiter
     *
     * @return string The scope delimiter (default: ",")
     */
    public function getScopeDelimiter();

    /**
     * Set the scope delimiter
     *
     * @param string $scopeDelimiter
     *
     * @return self
     */
    public function setScopeDelimiter($scopeDelimiter);
}