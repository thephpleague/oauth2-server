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

class TwigRenderer extends AbstractRenderer
{
    /**
     * @var \Twig_Environment
     */
    private $environment;

    /**
     * PlatesRenderer constructor.
     *
     * @param \Twig_Environment $environment
     * @param string            $loginTemplate
     * @param string            $authorizeTemplate
     */
    public function __construct(\Twig_Environment $environment, $loginTemplate, $authorizeTemplate)
    {
        parent::__construct($loginTemplate, $authorizeTemplate);

        $this->environment = $environment;
    }

    /**
     * {@inheritdoc}
     */
    protected function render($template, array $data = [])
    {
        return $this->environment->loadTemplate($template)->render($data);
    }
}
