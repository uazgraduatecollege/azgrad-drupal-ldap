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
    if (!ldap_servers_ldap_extension_loaded()) {
      drupal_set_message(t('PHP LDAP Extension is not loaded.'), "warning");
    }

    $https_approaches = [];
    $https_approaches[] = t('Use secure pages or secure login module to redirect to SSL (https)');
    $https_approaches[] = t('Run entire site with SSL (https)');
    $https_approaches[] = t('Remove logon block and redirect all /user page to https via webserver redirect');

    $form['#title'] = "Configure LDAP Preferences";
    $form['ssl'] = [
      '#type' => 'details',
      '#title' => t('Require HTTPS on Credential Pages'),
    ];

    $settings = array(
      '#theme' => 'item_list',
      '#items' => $https_approaches,
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
