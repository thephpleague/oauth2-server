<?php
/**
 * Template renderer Interface.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\TemplateRenderer;

interface RendererInterface
{
    /**
     * @param string $template
     * @param array  $data
     *
     * @return string
     */
    public function render($template, array $data = []);
}
