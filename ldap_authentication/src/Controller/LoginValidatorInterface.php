<?php

namespace Drupal\ldap_authentication\Controller;

/**
 * Handles the actual testing of credentials and authentication of users.
 */
interface LoginValidatorInterface {

  /**
   *
   */
  public function validateLogin();

  /**
   *
   */
  public function processLogin();

  /**
   *
   */
  public function checkAllowedExcluded();

  /**
   *
   */
  public function getDrupalUser();

  /**
   *
   */
  public function testCredentials();

}
