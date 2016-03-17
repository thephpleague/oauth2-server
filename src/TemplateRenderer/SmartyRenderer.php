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

class SmartyRenderer extends AbstractRenderer
{
    /**
     * Smarty class.
     *
     * @var \Smarty
     */
    private $smarty;

    /**
     * PlatesRenderer constructor.
     *
     * @param \Smarty $smarty
     * @param string  $loginTemplate
     * @param string  $authorizeTemplate
     */
    public function __construct(\Smarty $smarty, $loginTemplate, $authorizeTemplate)
    {
        parent::__construct($loginTemplate, $authorizeTemplate);

        $this->smarty = $smarty;
    }

    /**
     * {@inheritdoc}
     */
    protected function render($template, array $data = [])
    {
        $this->smarty->assign($data);

        $output = $this->smarty->fetch($template);

        $this->smarty->clear_assign(array_keys($data));

        return $output;
    }
}
