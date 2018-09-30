<?php

namespace Drupal\ldap_user\Event;

use Drupal\user\UserInterface;
use Symfony\Component\EventDispatcher\Event;

/**
 *
 */
class LdapUserUpdatedEvent extends Event {

  const EVENT_NAME = 'ldap_drupal_user_update';

  public $account;

  /**
   *
   */
  public function __construct(UserInterface $account) {
    $this->account = $account;
  }

}
