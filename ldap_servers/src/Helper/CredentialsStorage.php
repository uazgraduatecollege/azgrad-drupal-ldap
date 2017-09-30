<?php

namespace Drupal\ldap_servers\Helper;


class CredentialsStorage {

  private static $userDn = NULL;
  private static $userPassword = NULL;
  private static $validate = FALSE;

  /**
   * Stores the user DN as provided by other LDAP modules.
   *
   * @param string $userDn
   *   DN to store.
   */
  public static function storeUserDn($userDn) {
    self::$userDn = $userDn;
  }

  /**
   * Stores the password from user input.
   *
   * @param $password
   *   Password to store.
   */
  public static function storeUserPassword($password) {
    self::$userPassword = $password;
  }

  /**
   * Turn testing of user credentials on or off.
   *
   * @param $validate
   *   Defaults to false.
   */
  public static function testCredentials($validate) {
    self::$validate = $validate;
  }
  /**
   * Return the temporarily saved user DN.
   *
   * @return null|string
   *   Login name.
   */
  public static function getUserDn() {
    return self::$userDn;
  }

  /**
   * Return the temporarily saved user password.
   *
   * @return null|string
   *   Login password.
   */
  public static function getPassword() {
    return self::$userPassword;
  }

  /**
   * Whether the bind function will use these credentials.
   *
   * @return bool
   *   Defaults to false.
   */
  public static function validateCredentials() {
    return self::$validate;
  }
}