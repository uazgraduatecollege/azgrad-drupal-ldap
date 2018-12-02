<?php

namespace Drupal\ldap_user\Event;

use Drupal\user\UserInterface;
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
   * @param UserInterface $account
   */
  public function __construct($account) {
    $this->account = $account;
  }

}
