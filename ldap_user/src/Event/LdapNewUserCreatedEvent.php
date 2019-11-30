<?php

namespace Drupal\ldap_user\Event;

use Drupal\user\UserInterface;
use Symfony\Component\EventDispatcher\Event;

/**
 * LDAP User created event.
 */
class LdapNewUserCreatedEvent extends Event {

  public const EVENT_NAME = 'ldap_new_drupal_user_created';

  /**
   * Account.
   *
   * @var \Drupal\user\Entity\User
   */
  public $account;

  /**
   * Constructor.
   *
   * @param \Drupal\user\UserInterface $account
   *   Account.
   */
  public function __construct(UserInterface $account) {
    $this->account = $account;
  }

}
