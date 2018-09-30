<?php

namespace Drupal\ldap_user\Event;

use Symfony\Component\EventDispatcher\Event;

/**
 *
 */
class LdapUserLoginEvent extends Event {

  const EVENT_NAME = 'ldap_user_login';

  public $accountName;

  /**
   * LdapUserLoginEvent constructor.
   *
   * @param string $account_name
   */
  public function __construct($account_name) {
    $this->accountName = $account_name;
  }

}
