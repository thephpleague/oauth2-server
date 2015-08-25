<?php
namespace League\OAuth2\Server\ServerInterface;


interface RequestAware {
    /**
     * Sets the Request Object
     *
     * @param \Symfony\Component\HttpFoundation\Request The Request Object
     *
     * @return self
     */
    public function setRequest($request);

    /**
     * Gets the Request object. It will create one from the globals if one is not set.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest();
}