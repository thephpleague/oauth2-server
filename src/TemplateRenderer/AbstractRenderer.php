<?php
/**
 * Base template renderer.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\TemplateRenderer;

abstract class AbstractRenderer implements RendererInterface
{
    /**
     * @var string
     */
    protected $loginTemplate;

    /**
     * @var string
     */
    protected $authorizeTemplate;

    /**
     * PlatesRenderer constructor.
     *
     * @param string $loginTemplate
     * @param string $authorizeTemplate
     */
    public function __construct($loginTemplate, $authorizeTemplate)
    {
        $this->loginTemplate = $loginTemplate;
        $this->authorizeTemplate = $authorizeTemplate;
    }

    /**
     * Render login template.
     *
     * @param array $data
     *
     * @return string
     */
    public function renderLogin(array $data = [])
    {
        return $this->render($this->loginTemplate, $data);
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
        return $this->render($this->authorizeTemplate, $data);
    }

    /**
     * Render template.
     *
     * @param string $template
     * @param array  $data
     *
     * @return string
     */
    abstract protected function render($template, array $data = []);
}
