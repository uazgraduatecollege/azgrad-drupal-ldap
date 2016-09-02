<?php

/**
 * @file
 * LDAP User editing UI.
 */

use Symfony\Component\HttpFoundation\RedirectResponse;


/**
 * Form for adding, updating, and deleting a single ldap authorization mapping.
 */
function ldap_user_admin_form($form, &$form_state) {
  $ldap_user_conf = ldap_user_conf('admin');
  $form = $ldap_user_conf->drupalForm();
  return $form;
}

/**
 * Validate handler for the ldap_user_admin_form.
 */
function ldap_user_admin_form_validate($form, &$form_state) {

  $ldap_user_conf_admin = ldap_user_conf('admin');
  list($errors, $warnings) = $ldap_user_conf_admin->drupalFormValidate($form_state['values'], $form['#storage']);
  foreach ($errors as $error_name => $error_text) {
    $form_state->setErrorByName($error_name, t($error_text));
  }
  foreach ($warnings as $warning_name => $warning_text) {
    drupal_set_message($warning_text, 'warning');
  }
  $form_state['ldap_warnings'] = (boolean) (count($warnings) > 0);
}

/**
 * Submit handler function for ldap_user_admin_form.
 */
function ldap_user_admin_form_submit($form, &$form_state) {

  $ldap_user_conf = ldap_user_conf('admin');
  // Add form data to object and save or create.
  $ldap_user_conf->drupalFormSubmit($form_state['values'], $form['#storage']);

  if ($ldap_user_conf->hasError == FALSE) {
    drupal_set_message(t('LDAP user configuration saved'), 'status');
    return new RedirectResponse(\Drupal::url('ldap_user.admin_form'));
  }
  else {
    $form_state->setErrorByName($conf->errorName, $conf->errorMsg);
    $ldap_user_conf->clearError();
  }

}
