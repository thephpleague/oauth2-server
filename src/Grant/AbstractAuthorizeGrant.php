<?php
/**
 * Abstract authorization grant.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\TemplateRenderer\PlatesRenderer;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use League\Plates\Engine;

abstract class AbstractAuthorizeGrant extends AbstractGrant
{
    /**
     * @var \League\OAuth2\Server\TemplateRenderer\RendererInterface
     */
    protected $templateRenderer;

    /**
     * Retrieve template renderer.
     *
     * @return \League\OAuth2\Server\TemplateRenderer\RendererInterface
     */
    protected function getTemplateRenderer()
    {
        if (!$this->templateRenderer instanceof RendererInterface) {
            $this->templateRenderer = new PlatesRenderer(
                new Engine(__DIR__ . '/../TemplateRenderer/DefaultTemplates'),
                'login_user',
                'authorize_client'
            );
        }

        return $this->templateRenderer;
    }

    /**
     * @param string $uri
     * @param array  $params
     * @param string $queryDelimiter
     *
     * @return string
     */
    public function makeRedirectUri($uri, $params = [], $queryDelimiter = '?')
    {
        $uri .= (strstr($uri, $queryDelimiter) === false) ? $queryDelimiter : '&';
        return $uri . http_build_query($params);
    }
}
