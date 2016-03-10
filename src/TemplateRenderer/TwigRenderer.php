<?php
/**
 * Twig template renderer bridge.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\TemplateRenderer;

use Twig_Environment;

class TwigRenderer implements RendererInterface
{
    /**
     * @var \Twig_Environment
     */
    private $environment;

    /**
     * TwigRenderer constructor.
     *
     * @param \Twig_Environment $environment
     */
    public function __construct(Twig_Environment $environment)
    {
        $this->environment = $environment;
    }

    /**
     * {@inheritdoc}
     */
    public function render($template, array $data = [])
    {
        return $this->environment->loadTemplate($template)->render($data);
    }
}
