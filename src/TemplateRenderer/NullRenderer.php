<?php

namespace League\OAuth2\Server\TemplateRenderer;

final class NullRenderer implements RendererInterface
{
    /**
     * Render login template.
     *
     * @param array $data
     *
     * @return string
     */
    public function renderLogin(array $data = [])
    {
        throw new \RuntimeException('You are trying to render a template while using a NullRenderer');
    }

    /**
     * Render authorize template.
     *
     * @param array $data
     *
     * @return string
     */
    public function renderAuthorize(array $data = [])
    {
        throw new \RuntimeException('You are trying to render a template while using a NullRenderer');
    }
}
