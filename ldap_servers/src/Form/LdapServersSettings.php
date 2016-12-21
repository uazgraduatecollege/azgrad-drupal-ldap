<?php

namespace Drupal\ldap_servers\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 *
 */
class LdapServersSettings extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_servers_settings';
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $this->config('ldap_servers.settings')
      ->set('require_ssl_for_credentials', $values['require_ssl_for_credentials'])
      ->save();
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['ldap_servers.settings'];
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    if (!extension_loaded('ldap')) {
      drupal_set_message(t('PHP LDAP Extension is not loaded.'), 'warning');
    }

    $form['#title'] = "Configure LDAP Preferences";
    $form['ssl'] = [
      '#type' => 'fieldset',
      '#title' => t('Require HTTPS on Credential Pages'),
    ];

    $settings = array(
      '#theme' => 'item_list',
      '#items' => [
        t('Use secure pages or secure login module to redirect to SSL (https)'),
        t('Run entire site with SSL (https)'),
        t('Remove logon block and redirect all /user page to https via webserver redirect'),
      ],
      '#type' => 'ul',
    );

    $form['ssl']['require_ssl_for_credentials'] = array(
      '#type' => 'checkbox',
      '#title' => t('If checked, modules using LDAP will not allow credentials to
          be entered on or submitted to HTTP pages, only HTTPS. This option should be used with an
          approach to get all logon forms to be https, such as:') . drupal_render($settings),
      '#default_value' => \Drupal::config('ldap_servers.settings')->get('require_ssl_for_credentials'),
    );

    $form = parent::buildForm($form, $form_state);
    return $form;
  }

}
