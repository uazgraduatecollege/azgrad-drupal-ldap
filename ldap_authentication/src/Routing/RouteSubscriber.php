<?php

namespace Drupal\ldap_authentication\Routing;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Routing\RouteSubscriberBase;
use Symfony\Component\Routing\RouteCollection;

/**
 * Class RouteSubscriber.
 *
 * @package Drupal\ldap_authentication\Routing
 * Listens to the dynamic route events.
 */
class RouteSubscriber extends RouteSubscriberBase {

  /**
   * {@inheritdoc}
   */
  protected function alterRoutes(RouteCollection $collection) {
    if ($route = $collection->get('user.pass')) {
      $route->setRequirement('_custom_access', '\Drupal\ldap_authentication\Routing\RouteSubscriber::validateResetPasswordAllowed');
    }
  }

  /**
   * Checks whether password reset is allowed.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   Show password or not.
   */
  public static function validateResetPasswordAllowed() {
    if (\Drupal::currentUser()->isAnonymous()) {

      if (\Drupal::config('ldap_authentication.settings')->get('authenticationMode') == 'mixed') {
        return AccessResult::allowed();
      }

      // Hide reset password for anonymous users if LDAP-only authentication and
      // password updates are disabled, otherwise show.
      if (\Drupal::config('ldap_authentication.settings')->get('passwordOption') == 'allow') {
        return AccessResult::allowed();
      }
      else {
        return AccessResult::forbidden();
      }
    }
    else {
      return AccessResult::forbidden();
    }
  }

}
