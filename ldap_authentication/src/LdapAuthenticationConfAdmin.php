<?php

namespace Drupal\ldap_authentication;

use Drupal\Core\Url;
use Drupal\ldap_servers\Entity\Server;


class LdapAuthenticationConfAdmin extends LdapAuthenticationConf {

  /**
   * 0.  Logon Options.
   */
  public $authenticationModeDefault;
  public $authenticationModeOptions;

  protected $authenticationServersDescription;
  public $authenticationServersOptions = array();

  /**
   * 1.  User Login Interface.
   */
  protected $loginUIUsernameTxtDescription;
  protected $loginUIPasswordTxtDescription;
  protected $ldapUserHelpLinkUrlDescription;
  protected $ldapUserHelpLinkTextDescription;


  /**
   * 2.  LDAP User Restrictions.
   */

  protected $allowOnlyIfTextInDnDescription;
  protected $excludeIfTextInDnDescription;
  protected $allowTestPhpDescription;

  /**
   * 4. Email.
   */

  public $emailOptionDefault;
  public $emailOptionOptions;

  public $emailUpdateDefault;
  public $emailUpdateOptions;


  /**
   * 5. Single Sign-On / Seamless Sign-On.
   */

  public $ssoEnabledDescription;
  public $ssoRemoteUserStripDomainNameDescription;
  public $ldapImplementationOptions;
  public $cookieExpirePeriod;
  public $seamlessLogInDescription;
  public $cookieExpireDescription;
  public $ldapImplementationDescription;


  public $errorMsg = NULL;
  public $hasError = FALSE;
  public $errorName = NULL;

  /**
   *
   */
  public function clearError() {
    $this->hasError = FALSE;
    $this->errorMsg = NULL;
    $this->errorName = NULL;
  }

  /**
   *
   */
  public function save() {
    foreach ($this->saveable as $property) {
      $save[$property] = $this->{$property};
    }
    \Drupal::configFactory()->getEditable('ldap_authentication.settings')->set('ldap_authentication_conf', $save)->save();
    $this->load();
  }

  /**
   *
   */
  static public function getSaveableProperty($property) {
    $ldap_authentication_conf = \Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf');
    return isset($ldap_authentication_conf[$property]) ? $ldap_authentication_conf[$property] : FALSE;

  }

  /**
   *
   */
  static public function uninstall() {
    \Drupal::config('ldap_authentication.settings')->clear('ldap_authentication_conf')->save();
  }

  /**
   *
   */
  public function __construct() {
    parent::__construct();
    $this->emailUpdateDefault = self::$emailUpdateOnLdapChangeEnableNotify;
    $this->emailOptionDefault = self::$emailFieldRemove;
    $this->authenticationModeDefault = self::$mode_mixed;

    $factory = \Drupal::service('ldap.servers');
    $servers = $factory->getEnabledServers();
    if ($servers) {
      foreach ($servers as $sid => $ldap_server) {
        $enabled = ($ldap_server->get('status')) ? 'Enabled' : 'Disabled';
        $this->authenticationServersOptions[$sid] = $ldap_server->get('label') . ' (' . $ldap_server->get('address') . ') Status: ' . $enabled;
      }
    }
  }

  /**
   * Validate form, not object.
   */
  public function drupalFormValidate($values) {

    $this->populateFromDrupalForm($values);

    $errors = $this->validate();
    return $errors;
  }

  /**
   * Validate object, not form.
   */
  public function validate() {
    $errors = array();

    $factory = \Drupal::service('ldap.servers');
    $enabled_servers = $factory->getEnabledServers();

    if ($this->ssoEnabled) {
      foreach ($this->sids as $sid => $discard) {
        if ($enabled_servers[$sid]->get('bind_method') == Server::$bindMethodUser || $enabled_servers[$sid]->get('bind_method') == Server::$bindMethodAnonUser) {
          $methods = array(
            Server::$bindMethodUser => 'Bind with Users Credentials',
            Server::$bindMethodAnonUser => 'Anonymous Bind for search, then Bind with Users Credentials',
          );
          $tokens = array(
            '%edit' => \Drupal::l($enabled_servers[$sid]->name, Url::fromUri('/admin/config/people/ldap/servers/edit/' . $sid)),
            '%sid' => $sid,
            '%bind_method' => $methods[$enabled_servers[$sid]->get('bind_method')],
          );

          $errors['ssoEnabled'] = t('Single Sign On is not valid with the server !edit (id=%sid) because that server configuration uses %bind_method.  Since the user\'s credentials are never available to this module with single sign on enabled, there is no way for the ldap module to bind to the ldap server with credentials.', $tokens);
        }
      }
    }
    return $errors;
  }

  /**
   *
   */
  protected function populateFromDrupalForm($values) {

    $this->authenticationMode = ($values['authenticationMode']) ? (int) $values['authenticationMode'] : NULL;
    $this->sids = $values['authenticationServers'];
    $this->allowOnlyIfTextInDn = $this->linesToArray($values['allowOnlyIfTextInDn']);
    $this->excludeIfTextInDn = $this->linesToArray($values['excludeIfTextInDn']);
    $this->loginUIUsernameTxt = ($values['loginUIUsernameTxt']) ? (string) $values['loginUIUsernameTxt'] : NULL;
    $this->loginUIPasswordTxt = ($values['loginUIPasswordTxt']) ? (string) $values['loginUIPasswordTxt'] : NULL;
    $this->ldapUserHelpLinkUrl = ($values['ldapUserHelpLinkUrl']) ? (string) $values['ldapUserHelpLinkUrl'] : NULL;
    $this->ldapUserHelpLinkText = ($values['ldapUserHelpLinkText']) ? (string) $values['ldapUserHelpLinkText'] : NULL;
    $this->excludeIfNoAuthorizations = ($values['excludeIfNoAuthorizations']) ? (int) $values['excludeIfNoAuthorizations'] : NULL;
    $this->emailOption  = ($values['emailOption']) ? (int) $values['emailOption'] : NULL;
    $this->emailUpdate  = ($values['emailUpdate']) ? (int) $values['emailUpdate'] : NULL;
    $this->passwordOption  = ($values['passwordOption']) ? (int) $values['passwordOption'] : NULL;
    $this->ssoExcludedPaths = $this->linesToArray($values['ssoExcludedPaths']);
    $this->ssoExcludedHosts = $this->linesToArray($values['ssoExcludedHosts']);
    $this->ssoRemoteUserStripDomainName = ($values['ssoRemoteUserStripDomainName']) ? (int) $values['ssoRemoteUserStripDomainName'] : NULL;
    $this->seamlessLogin = ($values['seamlessLogin']) ? (int) $values['seamlessLogin'] : NULL;
    $this->cookieExpire = ($values['cookieExpire']) ? (int) $values['cookieExpire'] : NULL;
    $this->ldapImplementation = ($values['ldapImplementation']) ? (string) $values['ldapImplementation'] : NULL;

    foreach ($values['authenticationServers'] as $sid => $enabled) {
      if ($enabled) {
        $this->enabledAuthenticationServers[$sid] = $enabled;
      }
    };
  }

  /**
   *
   */
  public function drupalFormSubmit($values) {

    $this->populateFromDrupalForm($values);
    try {
      $save_result = $this->save();
    }
    catch (\Exception $e) {
      $this->errorName = 'Save Error';
      $this->errorMsg = t('Failed to save object.  Your form data was not saved.');
      $this->hasError = TRUE;
    }

  }

  /**
   *
   */
  public static function arrayToLines($array) {
    $lines = "";
    if (is_array($array)) {
      $lines = join("\n", $array);
    }
    elseif (is_array(@unserialize($array))) {
      $lines = join("\n", unserialize($array));
    }
    return $lines;
  }

  /**
   *
   */
  protected function linesToArray($lines) {
    $lines = trim($lines);

    if ($lines) {
      $array = preg_split('/[\n\r]+/', $lines);
      foreach ($array as $i => $value) {
        $array[$i] = trim($value);
      }
    }
    else {
      $array = array();
    }
    return $array;
  }

}
