<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;

/**
 * Class LdapHelpRedirect.
 *
 * @package Drupal\ldap_authentication\Controller
 */
class LdapHelpRedirect extends ControllerBase {

  /**
   * Redirect.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   Redirect response.
   */
  public function redirectUrl() {
    $url = \Drupal::config('ldap_authentication.settings')
      ->get('ldapUserHelpLinkUrl');
    return new TrustedRedirectResponse($url);
  }

}
