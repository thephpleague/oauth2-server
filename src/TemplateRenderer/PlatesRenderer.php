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

class PlatesRenderer extends AbstractRenderer
{
    /**
     * @var \League\Plates\Engine
     */
    private $engine;

    /**
     * PlatesRenderer constructor.
     *
     * @param \League\Plates\Engine $engine
     * @param string                $loginTemplate
     * @param string                $authorizeTemplate
     */
    public function __construct(Engine $engine, $loginTemplate, $authorizeTemplate)
    {
        parent::__construct($loginTemplate, $authorizeTemplate);

        $this->engine = $engine;
    }

    /**
     * {@inheritdoc}
     */
    protected function render($template, array $data = [])
    {
        if ($this->engine->getFileExtension()) {
            $template = preg_replace(sprintf('/\.%s$/', $this->engine->getFileExtension()), '', $template);
        }

        return $this->engine->render($template, $data);
    }
}
