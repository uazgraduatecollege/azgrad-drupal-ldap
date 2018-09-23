<?php

namespace Drupal\ldap_authentication\Plugin\Derivative;

use Drupal\Component\Plugin\Derivative\DeriverBase;
use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Plugin\Discovery\ContainerDeriverInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides help messages for users when configured.
 */
class DynamicUserHelpLink extends DeriverBase implements ContainerDeriverInterface {

  private $config;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   */
  public function __construct(ConfigFactory $config_factory) {
    $this->config = $config_factory->get('ldap_authentication.settings');
  }

  /**
   *
   */
  public static function create(ContainerInterface $container, $base_plugin_id) {
    return new static($container->get('config.factory'));
  }

  /**
   * {@inheritdoc}
   */
  public function getDerivativeDefinitions($basePluginDefinition) {
    if ($this->config->get('ldapUserHelpLinkText') &&
      $this->config->get('ldapUserHelpLinkUrl')) {
      $basePluginDefinition['title'] = $this->config->get('ldapUserHelpLinkText');
      $basePluginDefinition['route_name'] = 'ldap_authentication.ldap_help_redirect';
      $this->derivatives['ldap_authentication.show_user_help_link'] = $basePluginDefinition;
    }
    return $this->derivatives;
  }

}
