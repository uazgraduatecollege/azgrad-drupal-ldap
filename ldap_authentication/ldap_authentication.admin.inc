<?php

/**
 * @file
 * Administrative page callbacks for the ldap_authentication module.
 */

use Drupal\ldap_authentication\LdapAuthenticationConfAdmin;

/**
 * Form for adding, updating, and deleting a single ldap authorization mapping.
 *
 * @param mixed $form
 * @param mixed $form_state
 *
 * @return array drupal form array
 */
function ldap_authentication_admin_form($form, &$form_state) {
  $auth_conf = new LdapAuthenticationConfAdmin();
  return $auth_conf->drupalForm();
}

/**
 * Validate handler for the ldap_authentication_admin_form.
 */
function ldap_authentication_admin_form_validate($form, &$form_state) {
  $auth_conf = new LdapAuthenticationConfAdmin();
  $errors = $auth_conf->drupalFormValidate($form_state['values']);
  foreach ($errors as $error_name => $error_text) {
    $form_state->setErrorByName($error_name, t($error_text));
  }

}

/**
 * Submit handler function for ldap_authentication_admin_form.
 */
function ldap_authentication_admin_form_submit($form, &$form_state) {
  $auth_conf = new LdapAuthenticationConfAdmin();
  // Add form data to object and save or create.
  $auth_conf->drupalFormSubmit($form_state['values']);
  if (!$auth_conf->hasEnabledAuthenticationServers()) {
    drupal_set_message(t('No LDAP servers are enabled for authentication,
      so no LDAP Authentication can take place.  This essentially disables
      LDAP Authentication.'), 'warning');
  }
  if ($auth_conf->hasError == FALSE) {
    drupal_set_message(t('LDAP Authentication configuration saved'), 'status');
    return new RedirectResponse(\Drupal::url('ldap_user.admin_form'));
  }
  else {
    $form_state->setErrorByName($auth_conf->errorName, $auth_conf->errorMsg);
    $auth_conf->clearError();
  }

}
