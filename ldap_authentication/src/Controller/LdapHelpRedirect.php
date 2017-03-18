<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Class LdapHelpRedirect.
 *
 * @package Drupal\ldap_authentication\Controller
 */
class LdapHelpRedirect extends ControllerBase {
  /**
   * Redirect.
   *
   * @return TrustedRedirectResponse
   */
  public function redirectUrl() {
    $url = \Drupal::config('ldap_authentication.settings')
      ->get('ldapUserHelpLinkUrl');
    return new TrustedRedirectResponse($url);
  }
}
