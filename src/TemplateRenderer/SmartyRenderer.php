<?php
/**
 * Smarty template renderer bridge.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\TemplateRenderer;

use Smarty;

class SmartyRenderer implements RendererInterface
{
    /**
     * Smarty class.
     *
     * @var \Smarty
     */
    private $smarty;

    /**
     * @param \Smarty $smarty
     */
    public function __construct(Smarty $smarty)
    {
        $this->smarty = $smarty;
    }

    /**
     * {@inheritdoc}
     */
    public function render($template, array $data = [])
    {
        $this->smarty->assign($data);

        $output = $this->smarty->fetch($template);

        $this->smarty->clear_assign(array_keys($data));

        return $output;
    }
}
