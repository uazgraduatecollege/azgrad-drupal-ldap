<?php

namespace Drupal\ldap_user\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\ConfigFormBase;
use \Drupal\Core\Config\ConfigFactoryInterface;

use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 *
 */
class LdapUserAdminForm extends ConfigFormBase {

  protected $ldap_user_conf_admin;

  /**
   * {@inheritdoc}
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    parent::__construct($config_factory);
    $this->ldap_user_conf_admin = ldap_user_conf('admin');
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_user_admin_form';
  }

  /**
   * {@inheritdoc}
   */
  public function getEditableConfigNames() {
    return ['ldap_user_admin.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form = $this->ldap_user_conf_admin->drupalForm();
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    list($errors, $warnings) = $this->ldap_user_conf_admin->drupalFormValidate($form_state->getValues(), $form['#storage']);
    foreach ($errors as $error_name => $error_text) {
      $form_state->setErrorByName($error_name, $error_text);
    }
    foreach ($warnings as $warning_name => $warning_text) {
      drupal_set_message($warning_text, 'warning');
    }
    $form_state->set(['ldap_warnings'], (boolean) (count($warnings) > 0));
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Add form data to object and save or create.
    $this->ldap_user_conf_admin->drupalFormSubmit($form_state->getValues(), $form['#storage']);

    if ($this->ldap_user_conf_admin->hasError == FALSE) {
      drupal_set_message(t('LDAP user configuration saved'), 'status');
      return new RedirectResponse(\Drupal::url('ldap_user.admin_form'));
    }
    else {
      $form_state->setErrorByName($this->ldap_user_conf_admin->errorName, $this->ldap_user_conf_admin->errorMsg);
      $this->ldap_user_conf_admin->clearError();
    }
  }

}
