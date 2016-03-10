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
     * @var null|\League\OAuth2\Server\TemplateRenderer\RendererInterface
     */
    protected $templateRenderer;

    /**
     * @var null|string
     */
    protected $loginTemplate;

    /**
     * @var null|string
     */
    protected $authorizeTemplate;

    /**
     * @param array $data
     *
     * @return string
     */
    protected function renderLoginTemplate(array $data = [])
    {
        return $this->getTemplateRenderer()->render($this->getLoginTemplate(), $data);
    }

    /**
     * @param array $data
     *
     * @return string
     */
    protected function renderAuthorizeTemplate(array $data = [])
    {
        return $this->getTemplateRenderer()->render($this->getAuthorizeTemplate(), $data);
    }

    /**
     * @return \League\OAuth2\Server\TemplateRenderer\RendererInterface
     */
    protected function getTemplateRenderer()
    {
        if (!$this->templateRenderer instanceof RendererInterface) {
            $this->templateRenderer = new PlatesRenderer(new Engine(__DIR__ . '/../ResponseTypes/DefaultTemplates'));
        }

        return $this->templateRenderer;
    }

    /**
     * @return string
     */
    protected function getLoginTemplate()
    {
        if (empty($this->loginTemplate)) {
            $this->loginTemplate = 'login_user';
        }

        return $this->loginTemplate;
    }

    /**
     * @return string
     */
    protected function getAuthorizeTemplate()
    {
        if (empty($this->authorizeTemplate)) {
            $this->authorizeTemplate = 'authorize_client';
        }

        return $this->authorizeTemplate;
    }
}
