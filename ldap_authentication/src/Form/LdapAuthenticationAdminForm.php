<?php

namespace Drupal\ldap_authentication\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\ldap_authentication\LdapAuthenticationConfAdmin;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 *
 */
class LdapAuthenticationAdminForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_authentication_admin_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['ldap_authentication.settings'];
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $auth_conf = new LdapAuthenticationConfAdmin();
    return $auth_conf->drupalForm();
  }

  /**
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $auth_conf = new LdapAuthenticationConfAdmin();
    $errors = $auth_conf->drupalFormValidate($form_state->getValues());
    foreach ($errors as $error_name => $error_text) {
      $form_state->setErrorByName($error_name, t($error_text));
    }

  }

  /**
   *
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $auth_conf = new LdapAuthenticationConfAdmin();
    // Add form data to object and save or create.
    $auth_conf->drupalFormSubmit($form_state->getValues());
    if (!$auth_conf->hasEnabledAuthenticationServers()) {
      drupal_set_message(t('No LDAP servers are enabled for authentication,
      so no LDAP Authentication can take place.  This essentially disables
      LDAP Authentication.'), 'warning');
    }
    if ($auth_conf->hasError == FALSE) {
      drupal_set_message(t('LDAP Authentication configuration saved'), 'status');
      return new RedirectResponse(\Drupal::url('ldap_authentication.admin_form'));
    }
    else {
      // @FIXME
      // $form_state->setErrorByName($auth_conf->errorName, $auth_conf->errorMsg);
      $auth_conf->clearError();
    }

  }

}
