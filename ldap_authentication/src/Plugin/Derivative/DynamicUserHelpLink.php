<?php

namespace Drupal\ldap_authentication\Plugin\Derivative;

use Drupal\Component\Plugin\Derivative\DeriverBase;
use Drupal\Core\Access\AccessResultAllowed;
use Drupal\ldap_authentication\Helper\LdapAuthenticationConfiguration;

/**
 * Provides help messages for users when configured.
 */
class DynamicUserHelpLink extends DeriverBase {

  /**
   * {@inheritdoc}
   */
  public function getDerivativeDefinitions($base_plugin_definition) {
    $definitions = [];
    if ($this->accessLdapHelpTab()) {
      $definitions = $this->addLink($base_plugin_definition);
    }
    return $definitions;
  }

  /**
   * Access callback for help tab.
   *
   * @return bool
   *   Whether user is allowed to see tab or not.
   */
  private function accessLdapHelpTab() {
    $user = \Drupal::currentUser();
    $mode = \Drupal::config('ldap_authentication.settings')
      ->get('authenticationMode');
    if ($mode == LdapAuthenticationConfiguration::MODE_MIXED) {
      if (ldap_authentication_ldap_authenticated($user)) {
        return TRUE;
      }
    }
    elseif ($mode == LdapAuthenticationConfiguration::MODE_EXCLUSIVE) {
      if ($user->isAnonymous() || ldap_authentication_ldap_authenticated($user)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Drupal access callback.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   Access allowed or denied.
   */
  public function routeAccess() {
    if ($this->accessLdapHelpTab()) {
      return AccessResultAllowed::allowed();
    }
    else {
      return AccessResultAllowed::forbidden();
    }
  }

  /**
   * Provides the link itself.
   *
   * @return array
   *   The link.
   */
  private function addLink($base_plugin_definition) {
    if (\Drupal::config('ldap_authentication.settings')
      ->get('ldapUserHelpLinkText') && \Drupal::config('ldap_authentication.settings')
      ->get('ldapUserHelpLinkUrl')) {
      $this->derivatives['ldap_authentication.show_user_help_link'] = $base_plugin_definition;
      $this->derivatives['ldap_authentication.show_user_help_link']['title'] = \Drupal::config('ldap_authentication.settings')
        ->get('ldapUserHelpLinkText');
      $this->derivatives['ldap_authentication.show_user_help_link']['route_name'] = 'ldap_authentication.ldap_help_redirect';
      return $this->derivatives;
    }
  }

}
