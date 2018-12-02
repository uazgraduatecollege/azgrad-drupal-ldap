<?php

namespace Drupal\ldap_user\Event;

use Symfony\Component\EventDispatcher\Event;

/**
 *
 */
class LdapUserLoginEvent extends Event {

  const EVENT_NAME = 'ldap_user_login';

  public $account;

  /**
   * LdapUserLoginEvent constructor.
   *
   * @param \Drupal\user\UserInterface $account
   */
  public function __construct($account) {
    $this->account = $account;
  }

}
