<?php
/**
 * Mustache template renderer bridge.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\TemplateRenderer;

class MustacheRenderer extends AbstractRenderer
{
    /**
     * @var \Mustache_Engine
     */
    private $engine;

    /**
     * PlatesRenderer constructor.
     *
     * @param \Mustache_Engine $engine
     * @param string           $loginTemplate
     * @param string           $authorizeTemplate
     */
    public function __construct(\Mustache_Engine $engine, $loginTemplate, $authorizeTemplate)
    {
        parent::__construct($loginTemplate, $authorizeTemplate);

        $this->engine = $engine;
    }

    /**
     * {@inheritdoc}
     */
    public function render($template, array $data = [])
    {
        return $this->engine->render($template, $data);
    }
}
