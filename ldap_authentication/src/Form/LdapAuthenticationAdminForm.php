<?php

namespace Drupal\ldap_authentication\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Url;
use Drupal\ldap_authentication\Helper\LdapAuthenticationConfiguration;

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
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('ldap_authentication.settings');

    $factory = \Drupal::service('ldap.servers');
    $servers = $factory->getEnabledServers();
    $authenticationServers = [];
    if ($servers) {
      foreach ($servers as $sid => $ldap_server) {
        $enabled = ($ldap_server->get('status')) ? 'Enabled' : 'Disabled';
        $authenticationServers[$sid] = $ldap_server->get('label') . ' (' . $ldap_server->get('address') . ') Status: ' . $enabled;
      }
    }

    if (count($authenticationServers) == 0) {

      $url = Url::fromRoute('entity.ldap_server.collection');
      $edit_server_link = \Drupal::l(t('@path', array('@path' => 'LDAP Servers')), $url);

      $message = t('At least one LDAP server must configured and <em>enabled</em>
 before configuring LDAP authentication. Please go to @link to configure an LDAP server.',
        ['@link' => $edit_server_link]
      );

      $form['intro'] = array(
        '#type' => 'item',
        '#markup' => t('<h1>LDAP Authentication Settings</h1>') . $message,
      );
      return $form;
    }

    $form['intro'] = [
      '#type' => 'item',
      '#markup' => t('<h1>LDAP Authentication Settings</h1>'),
    ];

    $form['logon'] = [
      '#type' => 'fieldset',
      '#title' => t('Logon Options'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    ];

    $form['logon']['authenticationMode'] = [
      '#type' => 'radios',
      '#title' => t('Allowable Authentications'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.authenticationMode'),
      '#options' => [
        LdapAuthenticationConfiguration::MODE_MIXED => $this->t('Mixed mode: Drupal authentication is tried first. On failure, LDAP authentication is performed.'),
        LdapAuthenticationConfiguration::MODE_EXCLUSIVE => $this->t('Exclusive mode: Only LDAP Authentication is allowed, except for user 1.'),
      ],
      '#description' => $this->t('If exclusive is selected: <br> (1) reset password links will be replaced with links to ldap end user documentation below.<br>
        (2) The reset password form will be left available at user/password for user 1; but no links to it will be provided to anonymous users.<br>
        (3) Password fields in user profile form will be removed except for user 1.'),
    ];

    $form['logon']['authenticationServers'] = [
      '#type' => 'checkboxes',
      '#title' => t('Authentication LDAP Server Configurations'),
      '#required' => FALSE,
      '#default_value' => $config->get('ldap_authentication_conf.sids'),
      '#options' => $authenticationServers,
      '#description' =>  t('Check all LDAP server configurations to use in authentication.
     Each will be tested for authentication until successful or
     until each is exhausted.  In most cases only one server configuration is selected.'),
    ];

    $form['login_UI'] = array(
      '#type' => 'fieldset',
      '#title' => t('User Login Interface'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    $form['login_UI']['loginUIUsernameTxt'] = array(
      '#type' => 'textfield',
      '#title' => t('Username Description Text'),
      '#required' => 0,
      '#default_value' => $config->get('ldap_authentication_conf.loginUIUsernameTxt'),
      '#description' =>  $this->t('Text to be displayed to user below the username field of the user login screen.'),
    );

    $form['login_UI']['loginUIPasswordTxt'] = array(
      '#type' => 'textfield',
      '#title' => t('Password Description Text'),
      '#required' => 0,
      '#default_value' => $config->get('ldap_authentication_conf.loginUIPasswordTxt'),
      '#description' => $this->t('Text to be displayed to user below the password field of the user login screen.'),
    );

    $form['login_UI']['ldapUserHelpLinkUrl'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP Account User Help URL'),
      '#required' => 0,
      '#default_value' => $config->get('ldap_authentication_conf.ldapUserHelpLinkUrl'),
      '#description' => $this->t('URL to LDAP user help/documentation for users resetting
     passwords etc. Should be of form http://domain.com/. Could be the institutions ldap password support page
     or a page within this drupal site that is available to anonymous users.'),
    );

    $form['login_UI']['ldapUserHelpLinkText'] = [
      '#type' => 'textfield',
      '#title' => t('LDAP Account User Help Link Text'),
      '#required' => 0,
      '#default_value' => $config->get('ldap_authentication_conf.ldapUserHelpLinkText'),
      '#description' => $this->t('Text for above link e.g. Account Help or Campus Password Help Page'),
    ];

    $form['restrictions'] = [
      '#type' => 'fieldset',
      '#title' => t('LDAP User "Whitelists" and Restrictions'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    ];

    $form['restrictions']['allowOnlyIfTextInDn'] = [
      '#type' => 'textarea',
      '#title' => t('Allow Only Text Test'),
      '#default_value' => LdapAuthenticationConfiguration::arrayToLines($config->get('ldap_authentication_conf.allowOnlyIfTextInDn')),
      '#cols' => 50,
      '#rows' => 3,
      '#description' => $this->t('A list of text such as ou=education
      or cn=barclay that at least one of be found in user\'s dn string.  Enter one per line
      such as <pre>ou=education<br>ou=engineering</pre> This test will be case insensitive.'),
    ];

    $form['restrictions']['excludeIfTextInDn'] = array(
      '#type' => 'textarea',
      '#title' => t('Excluded Text Test'),
      '#default_value' => LdapAuthenticationConfiguration::arrayToLines($config->get('ldap_authentication_conf.excludeIfTextInDn')),
      '#cols' => 50,
      '#rows' => 3,
      '#description' => $this->t('A list of text such as ou=evil
      or cn=bad that if found in a user\'s dn, exclude them from ldap authentication.
      Enter one per line such as <pre>ou=evil<br>cn=bad</pre> This test will be case insensitive.'),
    );

    $form['restrictions']['excludeIfNoAuthorizations'] = array(
      '#type' => 'checkbox',
      '#title' => t('Deny access to users without Ldap Authorization Module
        authorization mappings such as Drupal roles.
        Requires LDAP Authorization to be enabled and configured!'),
      '#default_value' => $config->get('ldap_authentication_conf.excludeIfNoAuthorizations'),
      '#description' => $this->t('If the user is not granted any drupal roles,
      organic groups, etc. by LDAP Authorization, login will be denied.  LDAP Authorization must be
      enabled for this to work.'),
      '#disabled' => (boolean) (!\Drupal::moduleHandler()->moduleExists('ldap_authorization')),
    );

    $form['email'] = [
      '#type' => 'fieldset',
      '#title' => t('Email'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    ];

    $form['email']['emailOption'] = [
      '#type' => 'radios',
      '#title' => t('Email Behavior'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.emailOption'),
      '#options' =>  [
        LdapAuthenticationConfiguration::$emailFieldRemove => t('Don\'t show an email field on user forms. LDAP derived email will be used for user and cannot be changed by user.'),
        LdapAuthenticationConfiguration::$emailFieldDisable => t('Show disabled email field on user forms with LDAP derived email. LDAP derived email will be used for user and cannot be changed by user.'),
        LdapAuthenticationConfiguration::$emailFieldAllow => t('Leave email field on user forms enabled. Generally used when provisioning to LDAP or not using email derived from LDAP.'),
      ],
    ];

    $form['email']['emailUpdate'] = array(
      '#type' => 'radios',
      '#title' => t('Email Update'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.emailUpdate'),
      '#options' => [
        LdapAuthenticationConfiguration::$emailUpdateOnLdapChangeEnableNotify => t('Update stored email if LDAP email differs at login and notify user.'),
        LdapAuthenticationConfiguration::$emailUpdateOnLdapChangeEnable => t('Update stored email if LDAP email differs at login but don\'t notify user.'),
        LdapAuthenticationConfiguration::$emailUpdateOnLdapChangeDisable => t('Don\'t update stored email if LDAP email differs at login.'),
      ],
    );

    $form['password'] = array(
      '#type' => 'fieldset',
      '#title' => t('Password'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );
    $form['password']['passwordOption'] = array(
      '#type' => 'radios',
      '#title' => t('Password Behavior'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.passwordOption'),
      '#options' => [
        LdapAuthenticationConfiguration::$passwordFieldShowDisabled => t('Display password field disabled (Prevents password updates).'),
        LdapAuthenticationConfiguration::$passwordFieldHide => t('Don\'t show password field on user forms except login form.'),
        LdapAuthenticationConfiguration::$passwordFieldAllow => t('Display password field and allow updating it. In order to change password in LDAP, LDAP provisioning for this field must be enabled.'),
      ],
    );

    $form['submit'] = array(
      '#type' => 'submit',
      '#value' => 'Save',
    );

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Add form data to object and save or create.
    $values = $form_state->getValues();
    $this->config('ldap_authentication.settings')
      ->set('ldap_authentication_conf.authenticationMode', $values['authenticationMode'])
      ->set('ldap_authentication_conf.sids', $values['authenticationServers'])
      ->set('ldap_authentication_conf.allowOnlyIfTextInDn', LdapAuthenticationConfiguration::linesToArray($values['allowOnlyIfTextInDn']))
      ->set('ldap_authentication_conf.excludeIfTextInDn',  LdapAuthenticationConfiguration::linesToArray($values['excludeIfTextInDn']))
      ->set('ldap_authentication_conf.loginUIUsernameTxt', $values['loginUIUsernameTxt'])
      ->set('ldap_authentication_conf.loginUIPasswordTxt', $values['loginUIPasswordTxt'])
      ->set('ldap_authentication_conf.ldapUserHelpLinkUrl', $values['ldapUserHelpLinkUrl'])
      ->set('ldap_authentication_conf.ldapUserHelpLinkText', $values['ldapUserHelpLinkText'])
      ->set('ldap_authentication_conf.excludeIfNoAuthorizations', $values['excludeIfNoAuthorizations'])
      ->set('ldap_authentication_conf.emailOption', $values['emailOption'])
      ->set('ldap_authentication_conf.emailUpdate', $values['emailUpdate'])
      ->set('ldap_authentication_conf.passwordOption', $values['passwordOption'])
      ->save();

  }

}
