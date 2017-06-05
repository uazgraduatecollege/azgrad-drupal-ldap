<?php

namespace Drupal\ldap_help\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 *
 */
class LdapDebugSettings extends ConfigFormBase {

  /**
   *
  function ldap_help_form_ldap_servers_settings_alter(&$form, FormStateInterface $form_state) {
    $form['watchdog_detail'] = ['#type' => 'fieldset', '#title' => t('Debugging')];
    $form['watchdog_detail']
  }

  function ldap_help_watchdog_detail_submit(array &$form, FormStateInterface $form_state) {
    if ($form_state->isSubmitted()) {

    }
  }
   */

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_help_debug_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['ldap_help.settings'];
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state) {

    $form['#title'] = "Configure LDAP Preferences";
    $form['watchdog_detail'] = [
      '#type' => 'checkbox',
      '#title' => t('Enabled Detailed LDAP Watchdog logging.'),
      '#description' => t('This is generally useful for debugging and reporting issues with the LDAP modules and should not be left enabled in a production environment.'),
      '#default_value' => \Drupal::config('ldap_help.settings')->get('watchdog_detail'),
    ];
    $form = parent::buildForm($form, $form_state);
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->config('ldap_help.settings')
      ->set('watchdog_detail', $form_state->getValue('watchdog_detail'))
      ->save();
  }
}
