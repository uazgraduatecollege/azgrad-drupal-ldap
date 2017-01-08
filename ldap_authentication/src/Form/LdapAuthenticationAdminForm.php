<?php

namespace Drupal\ldap_authentication\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Url;
use Drupal\ldap_authentication\LdapAuthenticationConf;
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
    $config = $this->config('ldap_authentication.settings');

    //TODO Remove LdapAuthenticationConf
    $auth_conf = new LdapAuthenticationConfAdmin();
    $authenticationServersOptions = [
      LdapAuthenticationConf::$mode_mixed => t('Mixed mode. Drupal authentication is tried first.  On failure, LDAP authentication is performed.'),
      LdapAuthenticationConf::$mode_exclusive => t('Only LDAP Authentication is allowed except for user 1.
        If selected, (1) reset password links will be replaced with links to ldap end user documentation below.
        (2) The reset password form will be left available at user/password for user 1; but no links to it
        will be provided to anonymous users.
        (3) Password fields in user profile form will be removed except for user 1.'),
    ];

    if (count($authenticationServersOptions) == 0) {

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

    // Not sure what the tokens would be for this form?
    $tokens = array();

    $form['intro'] = array(
      '#type' => 'item',
      '#markup' => t('<h1>LDAP Authentication Settings</h1>'),
    );

    $form['logon'] = array(
      '#type' => 'fieldset',
      '#title' => t('Logon Options'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    $form['logon']['authenticationMode'] = array(
      '#type' => 'radios',
      '#title' => t('Allowable Authentications'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.authenticationMode'),
      '#options' => $authenticationServersOptions,
    );

    $form['logon']['authenticationServers'] = array(
      '#type' => 'checkboxes',
      '#title' => t('Authentication LDAP Server Configurations'),
      '#required' => FALSE,
      '#default_value' => $config->get('ldap_authentication_conf.sids'),
      '#options' => $auth_conf->authenticationServersOptions,
      '#description' =>  t('Check all LDAP server configurations to use in authentication.
     Each will be tested for authentication until successful or
     until each is exhausted.  In most cases only one server configuration is selected.'),
    );

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

    $form['login_UI']['ldapUserHelpLinkText'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP Account User Help Link Text'),
      '#required' => 0,
      '#default_value' => $config->get('ldap_authentication_conf.ldapUserHelpLinkText'),
      '#description' => $this->t('Text for above link e.g. Account Help or Campus Password Help Page'),
    );

    $form['restrictions'] = array(
      '#type' => 'fieldset',
      '#title' => t('LDAP User "Whitelists" and Restrictions'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    $form['restrictions']['allowOnlyIfTextInDn'] = array(
      '#type' => 'textarea',
      '#title' => t('Allow Only Text Test'),
      '#default_value' => LdapAuthenticationConfAdmin::arrayToLines($config->get('ldap_authentication_conf.allowOnlyIfTextInDn')),
      '#cols' => 50,
      '#rows' => 3,
      '#description' => $this->t('A list of text such as ou=education
      or cn=barclay that at least one of be found in user\'s dn string.  Enter one per line
      such as <pre>ou=education<br>ou=engineering</pre> This test will be case insensitive.'),
    );

    $form['restrictions']['excludeIfTextInDn'] = array(
      '#type' => 'textarea',
      '#title' => t('Excluded Text Test'),
      '#default_value' => LdapAuthenticationConfAdmin::arrayToLines($config->get('ldap_authentication_conf.excludeIfTextInDn')),
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

    $form['email'] = array(
      '#type' => 'fieldset',
      '#title' => t('Email'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    $form['email']['emailOption'] = array(
      '#type' => 'radios',
      '#title' => t('Email Behavior'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.emailOption'),
      '#options' =>  [
        LdapAuthenticationConf::$emailFieldRemove => t('Don\'t show an email field on user forms.  LDAP derived email will be used for user and connot be changed by user'),
        LdapAuthenticationConf::$emailFieldDisable => t('Show disabled email field on user forms with LDAP derived email.  LDAP derived email will be used for user and connot be changed by user'),
        LdapAuthenticationConf::$emailFieldAllow => t('Leave email field on user forms enabled.  Generally used when provisioning to LDAP or not using email derived from LDAP.'),
      ],
    );

    $form['email']['emailUpdate'] = array(
      '#type' => 'radios',
      '#title' => t('Email Update'),
      '#required' => 1,
      '#default_value' => $config->get('ldap_authentication_conf.emailUpdate'),
      '#options' => [
        LdapAuthenticationConf::$emailUpdateOnLdapChangeEnableNotify => t('Update stored email if LDAP email differs at login and notify user.'),
        LdapAuthenticationConf::$emailUpdateOnLdapChangeEnable => t('Update stored email if LDAP email differs at login but don\'t notify user.'),
        LdapAuthenticationConf::$emailUpdateOnLdapChangeDisable => t('Don\'t update stored email if LDAP email differs at login.'),
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
        LdapAuthenticationConf::$passwordFieldShow => t('Display password field disabled (Prevents password updates).'),
        LdapAuthenticationConf::$passwordFieldHide => t('Don\'t show password field on user forms except login form.'),
        LdapAuthenticationConf::$passwordFieldAllow => t('Display password field and allow updating it. In order to change password in LDAP, LDAP provisioning for this field must be enabled.'),
      ],
    );

    /**
     * Begin single sign-on settings
     */
    $form['sso'] = array(
      '#type' => 'fieldset',
      '#title' => t('Single Sign-On'),
      '#collapsible' => TRUE,
      '#collapsed' => (boolean) (!$auth_conf->ssoEnabled),
    );

    if ($auth_conf->ssoEnabled) {
      $form['sso']['enabled'] = array(
        '#type' => 'markup',
        '#markup' => '<strong>' . t('Single Sign on is enabled.') .
          '</strong> ' . t('To disable it, disable the LDAP SSO Module on the') . ' ' .
          \Drupal::l(t('Modules Form'), Url::fromRoute('system.modules_list')) .
          '.<p>' . t('Single Sign-On enables ' .
            'users of this site to be authenticated by visiting the URL ' .
            '"user/login/sso, or automatically if selecting "automated ' .
            'single sign-on" below. Set up of LDAP authentication must be ' .
            'performed on the web server. Please review the readme file ' .
            'for more information.') . '</p>',
      );
    }
    else {
      $form['sso']['disabled'] = array(
        '#type' => 'markup',
        '#markup' => '<p><em>' . t('LDAP Single Sign-On module must be enabled for options below to work.')
          . ' ' . t('It is currently disabled.')
          . ' ' . \Drupal::l(t('See modules form'), Url::fromRoute('system.modules_list')) . '</p></em>',
      );
    }

    $form['sso']['ssoRemoteUserStripDomainName'] = array(
      '#type' => 'checkbox',
      '#title' => t('Strip REMOTE_USER domain name'),
      '#description' => $this->t('Useful when the ' .
        'WWW server provides authentication in the form of user@realm and you ' .
        'want to have both SSO and regular forms based authentication ' .
        'available. Otherwise duplicate accounts with conflicting e-mail ' .
        'addresses may be created.'),
      '#default_value' => $auth_conf->ssoRemoteUserStripDomainName,
      '#disabled' => (boolean) (!$auth_conf->ssoEnabled),
    );

    $form['sso']['seamlessLogin'] = array(
      '#type' => 'checkbox',
      '#title' => t('Turn on automated single sign-on'),
      '#description' => $this->t('This requires that you ' .
        'have operational NTLM or Kerberos authentication turned on for at least ' .
        'the path user/login/sso, or for the whole domain.'),
      '#default_value' => $auth_conf->seamlessLogin,
      '#disabled' => (boolean) (!$auth_conf->ssoEnabled),
    );

    $form['sso']['cookieExpire'] = array(
      '#type' => 'select',
      '#title' => t('Cookie Lifetime'),
      '#description' => $this->t('If using the seamless login, a ' .
        'cookie is necessary to prevent automatic login after a user ' .
        'manually logs out. Select the lifetime of the cookie.'),
      '#default_value' => $auth_conf->cookieExpire,
      '#options' => [
        -1 => t('Session'),
        0 => t('Immediately')
      ],
      '#disabled' => (boolean) (!$auth_conf->ssoEnabled),
    );

    $form['sso']['ldapImplementation'] = array(
      '#type' => 'select',
      '#title' => t('Authentication Mechanism'),
      '#description' => $this->t('Select the type of authentication mechanism you are using.'),
      '#default_value' => $auth_conf->ldapImplementation,
      '#options' => [
        'mod_auth_sspi' => t('mod_auth_sspi'),
        'mod_auth_kerb' => t('mod_auth_kerb'),
      ],
      '#disabled' => (boolean) (!$auth_conf->ssoEnabled),
    );

    $form['sso']['ssoExcludedPaths'] = array(
      '#type' => 'textarea',
      '#title' => t('SSO Excluded Paths'),
      '#description' => $this->t('Which paths will not check for SSO? cron.php is common example. Specify pages by using their paths. Enter one path per line. The \'*\' character is a wildcard.
        Example paths are %blog for the blog page and %blog-wildcard for every personal blog. %front is the front page.',
        ['%blog' => 'blog', '%blog-wildcard' => 'blog/*', '%front' => '<front>']),
      '#default_value' => $auth_conf->arrayToLines($auth_conf->ssoExcludedPaths),
      '#disabled' => (boolean) (!$auth_conf->ssoEnabled),
    );

    $form['sso']['ssoExcludedHosts'] = array(
      '#type' => 'textarea',
      '#title' => t('SSO Excluded Hosts'),
      '#description' => $this->t('If your site is accessible via multiple hostnames, you may only want
        the LDAP SSO module to authenticate against some of them. To exclude
        any hostnames from SSO, enter them here. Enter one host per line.'),
      '#default_value' => $auth_conf->arrayToLines($auth_conf->ssoExcludedHosts),
      '#disabled' => (boolean) (!$auth_conf->ssoEnabled),
    );

    $form['submit'] = array(
      '#type' => 'submit',
      '#value' => 'Save',
    );

    return $form;
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
