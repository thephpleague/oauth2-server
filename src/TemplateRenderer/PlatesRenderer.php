<?php
/**
 * Plates template renderer bridge.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\TemplateRenderer;

use League\Plates\Engine;

class PlatesRenderer implements RendererInterface
{
    /**
     * @var \League\Plates\Engine
     */
    private $engine;

    /**
     * PlatesRenderer constructor.
     *
     * @param \League\Plates\Engine $engine
     */
    public function __construct(Engine $engine)
    {
        $this->engine = $engine;
    }

    /**
     * {@inheritdoc}
     */
    public function render($template, array $data = [])
    {
        if ($this->engine->getFileExtension()) {
            $template = preg_replace(sprintf('/\.%s$/', $this->engine->getFileExtension()), '', $template);
        }

        return $this->engine->render($template, $data);
    }
}
