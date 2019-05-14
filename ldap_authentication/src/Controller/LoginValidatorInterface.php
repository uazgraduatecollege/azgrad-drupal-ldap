<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Handles the actual testing of credentials and authentication of users.
 */
interface LoginValidatorInterface {

  /**
   * Starts login process.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return \Drupal\Core\Form\FormStateInterface
   *   The form state.
   */
  public function validateLogin(FormStateInterface $form_state);

  /**
   * Perform the actual logging in.
   *
   * @return void
   *   Check result via getDrupalUser().
   */
  public function processLogin(): void;

  /**
   * Check if exclusion criteria match.
   *
   * @param string $authName
   *   Authname.
   * @param \Symfony\Component\Ldap\Entry $ldap_user
   *   LDAP Entry.
   *
   * @return bool
   *   Exclusion result.
   */
  public function checkAllowedExcluded($authName, Entry $ldap_user);

  /**
   * Returns the derived user account.
   *
   * @return \Drupal\user\Entity\User
   *   User account.
   */
  public function getDrupalUser();

  /**
   * Credentials are tested.
   *
   * @return int
   *   Returns the authentication result.
   */
  public function testCredentials();

}
