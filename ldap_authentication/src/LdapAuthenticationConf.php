<?php

namespace Drupal\ldap_authentication;

use Drupal\Core\Url;

/**
 *
 */
class LdapAuthenticationConf {

  /**
   * Server configuration ids being used for authentication.
   *
   * @var array
   *
   * @see LdapServer::sid()
   */
  public $sids = array();

  /**
   * Server configuration ids being used for authentication.
   *
   * @var array
   *  Associative array of LdapServer objects keyed on sids.
   *
   * @see LdapServer::sid
   * @see LdapServer
   */
  public $enabledAuthenticationServers = array();

  /**
   * Has current object been saved to the database?
   *
   * @var bool
   */
  public $inDatabase = FALSE;

  // Signifies both LDAP and Drupal authentication are allowed.
  // Drupal authentication is attempted first.
  public static $mode_mixed = 1;
  // Signifies only LDAP authentication is allowed.
  public static $mode_exclusive = 2;

  /**
   * Choice of authentication modes.
   */
  public $authenticationMode;

  /**
   * The following are used to alter the logon interface to direct users
   * to local LDAP specific authentication help.
   */

  /**
   * Text describing username to use, such as "Hogwarts Username"
   *  which will be inserted on logon forms to help users figure out which
   *  username to use.
   *
   * @var string
   */
  public $loginUIUsernameTxt;

  /**
   * Text describing password to use, such as "Hogwards LDAP Password"
   *  which will be inserted on logon forms.  Useful in organizations with
   *  multiple account types for authentication.
   *
   * @var string
   */
  public $loginUIPasswordTxt;

  /**
   * Text and Url to provide help link for password such as:
   *   ldapUserHelpLinkUrl:    https://passwords.hogwarts.edu
   *   ldapUserHelpLinkText:  Hogwarts IT Password Support Page.
   *
   * @var string
   */
  public $ldapUserHelpLinkUrl;
  public $ldapUserHelpLinkText = 'login help';

  public static $authFailConnect = 1;
  public static $authFailBind = 2;
  public static $authFailFind = 3;
  public static $authFailDisallowed = 4;
  public static $authFailCredentials = 5;
  public static $authSuccess = 6;
  public static $authFailGeneric = 7;
  public static $authFailServer = 8;

  public static $emailFieldRemove = 2;
  public static $emailFieldDisable = 3;
  public static $emailFieldAllow = 4;
  // Remove default later if possible, see also $emailOption.
  public static $emailFieldDefault = 3;

  /**
   * Email handling option
   *   See above for possible values.
   *
   * @var int
   */
  public $emailOption;


  public static $emailUpdateOnLdapChangeEnableNotify = 1;
  public static $emailUpdateOnLdapChangeEnable = 2;
  public static $emailUpdateOnLdapChangeDisable = 3;
  // Remove default later if possible, see also $emailUpdate.
  public static $emailUpdateOnLdapChangeDefault = 1;

  /**
   * Email handling option
   *   See above for possible values.
   *
   * @var int
   */
  public $emailUpdate;

  public static $passwordFieldShow = 2;
  public static $passwordFieldHide = 3;
  public static $passwordFieldAllow = 4;
  // Remove default later if possible, see also $passwordOption.
  public static $passwordFieldDefault = 2;

  /**
   * Password handling option
   *   See above for possible values.
   *
   * @var int
   */
  public $passwordOption;

  public $ssoEnabled = FALSE;
  public $ssoRemoteUserStripDomainName = FALSE;
  public $ssoExcludedPaths = NULL;
  public $ssoExcludedHosts = NULL;
  public $seamlessLogin = FALSE;
  public $ldapImplementation = FALSE;
  public $cookieExpire = 0;

  public $apiPrefs = array();

  /**
   * Advanced options.   whitelist / blacklist options.
   *
   * These are on the fuzzy line between authentication and authorization
   * and determine if a user is allowed to authenticate with ldap.
   */

  /**
   * Text which must be present in user's LDAP entry's DN for user to authenticate with LDAP
   *   e.g. "ou=people".
   *
   * @var string
   */
  // Eg ou=education that must be met to allow ldap authentication.
  public $allowOnlyIfTextInDn = array();

  /**
   * Text which prohibits logon if found in user's LDAP entry's DN for user to authenticate with LDAP
   *   e.g. "ou=guest accounts".
   *
   * @var string
   */
  public $excludeIfTextInDn = array();

  /**
   * If at least 1 ldap authorization must exist for user to be allowed
   *   True signfies disallow if no authorizations.
   *   False signifies don't consider authorizations.
   *
   * @var bool
   */
  public $excludeIfNoAuthorizations = FALSE;

  public $saveable = array(
    'sids',
    'authenticationMode',
    'loginUIUsernameTxt',
    'loginUIPasswordTxt',
    'ldapUserHelpLinkUrl',
    'ldapUserHelpLinkText',
    'emailOption',
    'emailUpdate',
    'passwordOption',
    'allowOnlyIfTextInDn',
    'excludeIfTextInDn',
    'excludeIfNoAuthorizations',
    'ssoRemoteUserStripDomainName',
    'ssoExcludedPaths',
    'ssoExcludedHosts',
    'seamlessLogin',
    'ldapImplementation',
    'cookieExpire',
  );

  /**
   *
   */
  public function hasEnabledAuthenticationServers() {
    return !(count($this->enabledAuthenticationServers) == 0);
  }

  /**
   *
   */
  public function __construct() {
    $this->authenticationMode = self::$mode_mixed;
    $this->emailUpdate = self::$emailUpdateOnLdapChangeEnableNotify;
    $this->emailOption = self::$emailFieldDisable;
    $this->passwordOption = self::$passwordFieldHide;

    $this->load();
  }

  /**
   *
   */
  public function load() {

    if ($saved = \Drupal::config('ldap_authentication.settings')->get("ldap_authentication_conf")) {
      $this->inDatabase = TRUE;
      foreach ($this->saveable as $property) {
        if (isset($saved[$property])) {
          $this->{$property} = $saved[$property];
        }
      }
      // Reset in case reloading instantiated object.
      $this->enabledAuthenticationServers = array();
      $factory = \Drupal::service('ldap.servers');
      $enabled_ldap_servers = $factory->getEnabledServers();
      foreach ($this->sids as $sid => $enabled) {
        if ($enabled && isset($enabled_ldap_servers[$sid])) {
          $this->enabledAuthenticationServers[$sid] = $enabled_ldap_servers[$sid];
        }
      }

    }
    else {
      $this->inDatabase = FALSE;
    }
    $this->ssoEnabled = \Drupal::moduleHandler()->moduleExists('ldap_sso');
    $this->apiPrefs['requireHttps'] = \Drupal::config('ldap_servers.settings')->get('require_ssl_for_credentials');
  }

}
