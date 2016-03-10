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

use Mustache_Engine;

class MustacheRenderer implements RendererInterface
{
    /**
     * @var \Mustache_Engine
     */
    private $engine;

    /**
     * TwigRenderer constructor.
     *
     * @param \Mustache_Engine $engine
     */
    public function __construct(Mustache_Engine $engine)
    {
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
