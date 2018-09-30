<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_user\Event\LdapUserLoginEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class UpdateLdapEntry.
 */
class LdapLoginSubscriber implements EventSubscriberInterface {

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[LdapUserLoginEvent::EVENT_NAME] = ['xxx'];
    return $events;
  }

}
