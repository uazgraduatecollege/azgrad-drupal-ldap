<?php

/**
 * @file
 * Contains \Drupal\ldap_servers\Form\LdapServersSettings.
 */

namespace Drupal\ldap_servers\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\Element;

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
    $encryption = $values['encryption'] ? $values['encryption'] : LDAP_SERVERS_ENC_TYPE_CLEARTEXT;
    $this->config('ldap_servers.settings')
      ->set('require_ssl_for_credentials', $values['require_ssl_for_credentials'])
      ->set('encryption', $encryption)
      // ->set('previous_encryption', $values['previous_encryption'])
      ->save();

    if (method_exists($this, '_submitForm')) {
      $this->_submitForm($form, $form_state);
    }
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['ldap_servers.settings'];
  }

  public function buildForm(array $form, \Drupal\Core\Form\FormStateInterface $form_state) {
    if (!ldap_servers_ldap_extension_loaded()) {
      drupal_set_message(t('PHP LDAP Extension is not loaded.'), "warning");
    }

    $https_approaches = [];
    $https_approaches[] = t('Use secure pages or secure login module to redirect to SSL (https)');
    $https_approaches[] = t('Run entire site with SSL (https)');
    $https_approaches[] = t('Remove logon block and redirect all /user page to https via webserver redirect');

    $form['#title'] = "Configure LDAP Preferences";
    $form['ssl'] = [
      '#type' => 'fieldset',
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

    $options = ldap_servers_encrypt_types('encrypt');
    // @FIXME
    // Could not extract the default value because it is either indeterminate, or
    // not scalar. You'll need to provide a default value in
    // config/install/ldap_servers.settings.yml and config/schema/ldap_servers.schema.yml.
    /**  when this is changed, need to decrypt and possibly encrypt pwd in newly selected format
     *   ... thus default needs to be "No Encryption" to avoid confusion.
     */
    $form['previous_encryption'] = [
      '#type' => 'text',
      '#default_value' => \Drupal::config('ldap_servers.settings')->get('encryption'),
    ];
    $form['encryption'] = ['#type' => 'fieldset', '#title' => t('Encryption')];
    // @FIXME
    // Could not extract the default value because it is either indeterminate, or
    // not scalar. You'll need to provide a default value in
    // config/install/ldap_servers.settings.yml and config/schema/ldap_servers.schema.yml.
    $form['encryption']['encryption'] = [
      '#type' => 'select',
      '#options' => $options,
      '#title' => t('Encrypt Stored LDAP Passwords?'),
      '#default_value' => \Drupal::config('ldap_servers.settings')->get('encryption'),
      '#description' => t('With encryption, passwords will be stored in encrypted form.
    This is two way encryption because the actual password needs to used to bind to LDAP.
    So it offers minimal defense if someone gets in the filespace.  It mainly helps avoid the accidental
    discovery of a clear text password.'),
    ];


    // $options will be empty if server does not support mcrypt.
    // Disable the form field and explain this to the user.
    if (empty($options)) {
      $form['encryption']['encryption']['#options'] = [
        LDAP_SERVERS_ENC_TYPE_CLEARTEXT => t('Not available.')
        ];
      $form['encryption']['encryption']['#disabled'] = TRUE;
      $form['encryption']['encryption']['#description'] .= ' <strong>' . t('Encryption is not supported on this web server.') . '</strong>';
    }

    $form = parent::buildForm($form, $form_state);
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function _submitForm(array &$form, \Drupal\Core\Form\FormStateInterface $form_state) {
    if ($form_state->isSubmitted()) {
      $new_encryption = $form_state->getValue(['encryption']);
      $old_encryption = $form_state->getValue(['previous_encryption']);

      if ($new_encryption != $old_encryption) {
        $servers = ldap_servers_get_servers();
        foreach ($servers as $id => $server) {
          if ($server->bindpw != '') {
            $decrypted_bind_pwd = ldap_servers_decrypt($server->get('bindpw'), $old_encryption);
            $rencrypted = ldap_servers_encrypt($decrypted_bind_pwd, $new_encryption);
          }
          else {
            $rencrypted = '';
          }
          $server->set('bindpw', $rencrypted);
          $server->save();
        }
      }
    }
  }

}
