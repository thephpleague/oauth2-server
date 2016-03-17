<?php

namespace League\OAuth2\Server\TemplateRenderer;

interface RendererInterface
{
    /**
     * Render login template.
     *
     * @param array $data
     *
     * @return string
     */
    public function renderLogin(array $data = []);

    /**
     * Render authorize template.
     *
     * @param array $data
     *
     * @return string
     */
    public function renderAuthorize(array $data = []);
}
