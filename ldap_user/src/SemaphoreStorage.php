<?php

namespace Drupal\ldap_user;


class SemaphoreStorage {

  private static $accounts = [];

  public static function set($action, $identifier) {
    self::$accounts[$action][$identifier] = TRUE;
  }

  public static function get($action, $identifier) {
    if (isset(self::$accounts[$action], self::$accounts[$action][$identifier])) {
      return TRUE;
    } else {
      return FALSE;
    }
  }
  public static function flushValue($action, $identifier) {
    unset(self::$accounts[$action][$identifier]);
  }

  public static function flushAllValues() {
    self::$accounts = [];
  }

}