<?php

namespace Drupal\ldap_authentication\Access;

use Drupal\Core\Access\AccessResultAllowed;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Routing\Access\AccessInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\externalauth\Authmap;

/**
 * Checks whether the use is allowed to see the help tab.
 */
class UserHelpTabAccess implements AccessInterface {

  private $config;
  private $currentUser;
  private $externalAuth;

  /**
   * Constructor.
   */
  public function __construct(ConfigFactoryInterface $config_factory, AccountInterface $current_user, Authmap $external_auth) {
    $this->config = $config_factory->get('ldap_authentication.settings');
    $this->currentUser = $current_user;
    $this->externalAuth = $external_auth;
  }

  /**
   * Access callback for help tab.
   *
   * @return bool
   *   Whether user is allowed to see tab or not.
   */
  public function accessLdapHelpTab() {
    $mode = $this->config->get('authenticationMode');
    if ($mode == 'mixed') {
      if ($this->externalAuth->get($this->currentUser->id(), 'ldap_user')) {
        return TRUE;
      }
    }
    else {
      if ($this->currentUser->isAnonymous() ||
        $this->externalAuth->get($this->currentUser->id(), 'ldap_user')) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function access(AccountInterface $account) {
    if ($this->accessLdapHelpTab()) {
      return AccessResultAllowed::allowed();
    }
    else {
      return AccessResultAllowed::forbidden();
    }
  }

}
