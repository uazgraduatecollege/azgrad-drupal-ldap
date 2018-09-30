<?php

namespace Drupal\ldap_user\Event;

use Drupal\user\UserInterface;
use Symfony\Component\EventDispatcher\Event;

/**
 *
 */
class LdapNewUserCreatedEvent extends Event {

  const EVENT_NAME = 'ldap_new_drupal_user_created';

  public $account;

  /**
   *
   */
  public function __construct(UserInterface $account) {
    $this->account = $account;
  }

}
