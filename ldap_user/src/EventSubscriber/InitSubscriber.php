<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_user\SemaphoreStorage;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 *
 */
class InitSubscriber implements EventSubscriberInterface {

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    return [KernelEvents::REQUEST => ['onEvent', 0]];
  }

  /**
   *
   */
  public function onEvent() {
    // Reset for simpletest page load behavior.
    SemaphoreStorage::flushAllValues();
  }

}
