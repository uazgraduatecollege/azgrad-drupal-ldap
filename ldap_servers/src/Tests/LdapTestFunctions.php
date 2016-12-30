<?php

namespace Drupal\ldap_servers\tests;

/**
 * @file
 * Utility functions for ldap simpletests.
 *
 * @todo could be moved into LdapWebTestBase.php
 */

use Drupal\Component\Utility\Unicode;
use Drupal\ldap_authentication\LdapAuthenticationConf;
use Drupal\ldap_authentication\LdapAuthenticationConfAdmin;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\LdapProtocol;
use Drupal\ldap_user\LdapUserConf;

/**
 *
 */
class LdapTestFunctions implements LdapProtocol {

  public $data = array();
  // Data in ldap array format, but keyed on dn.
  public $ldapData = array();
  public $csvTables = array();
  public $ldapTypeConf;

  /**
   *
   */
  public function __construct() {
    $this->data['ldap_servers'] = $this->ldap_test_ldap_servers_data();
    // $this->data['ldap_user'] = $this->ldap_test_ldap_user_data();
    $this->data['ldap_authorization'] = $this->ldap_test_ldap_authorization_data();
    // Next TODO
    // $this->data['ldap_authentication'] = $this->ldap_test_ldap_authentication_data();
  }

  /**
   *
   */
  public function configureLdapServers($sids, $features = FALSE, $feature_name = NULL) {
    foreach ($sids as $i => $sid) {
      $current_sids[$sid] = $sid;
      // @FIXME variable_set('ldap_test_server__' . $sid, $this->data['ldap_servers'][$sid]);
    }
    // @FIXME variable_set('ldap_test_servers', $current_sids);
  }

  /**
   *
   */
  public function setFakeServerProperty($sid, $prop, $value) {
    // @FIXME  $test_data = variable_get('ldap_test_server__' . $sid, array());
    $test_data['properties'][$prop] = $value;
    // @FIXME  variable_set('ldap_test_server__' . $sid, $test_data);
  }

  /**
   *
   */
  public function setFakeServerUserAttribute($sid, $dn, $attr_name, $attr_value, $i = 0) {
    $attr_name = Unicode::strtolower($attr_name);
    // @FIXME: $test_data = variable_get('ldap_test_server__' . $sid, array());

    $test_data['entries'][$dn][$attr_name][$i] = $attr_value;
    $count_set = (int) isset($test_data['entries'][$dn][$attr_name]['count']);
    // don't count the 'count'.
    $test_data['entries'][$dn][$attr_name]['count'] = count($test_data['entries'][$dn][$attr_name]) - $count_set;

    $test_data['ldap'][$dn][$attr_name][$i] = $attr_value;
    $count_set = (int) isset($test_data['ldap'][$dn][$attr_name]['count']);
    // don't count the 'count'.
    $test_data['ldap'][$dn][$attr_name]['count'] = count($test_data['ldap'][$dn][$attr_name]) - $count_set;
    // @FIXME: variable_set('ldap_test_server__' . $sid, $test_data);
  }

  /**
   *
   */
  public function configureLdapAuthentication($ldap_authentication_test_conf_id, $sids) {
    module_load_include('php', 'ldap_authentication', 'LdapAuthenticationConfAdmin.class');
    $options = $this->data['ldap_authentication'][$ldap_authentication_test_conf_id];
    foreach ($sids as $i => $sid) {
      $options['sids'][$sid] = $sid;
    }
    $ldapServerAdmin = new LdapAuthenticationConfAdmin();
    foreach ($ldapServerAdmin->saveable as $prop_name) {
      if (isset($options[$prop_name])) {
        $ldapServerAdmin->{$prop_name} = $options[$prop_name];
      }
    }
    $ldapServerAdmin->save();
  }

  /**
   *
   */
  public function configureLdapUser($ldap_user_test_conf_id) {
    // @FIXME: Broken due to removed LdapUserConfAdmin
    $ldapUserConf = new LdapUserConf();
    $options = $this->data['ldap_user'][$ldap_user_test_conf_id];
    foreach ($ldapUserConf->saveable as $prop_name) {
      if (isset($options[$prop_name])) {
        $ldapUserConf->{$prop_name} = $options[$prop_name];
      }
    }
    // @FIXME: Format not up-to-date
    // $ldapUserConf->save();
  }

  /**
   *
   */
  public function prepConsumerConf($consumer_confs) {
    // @ FIXME: Just a placeholder
    return $consumer_confs;
  }

  /**
   * Function prepConsumerConf($consumer_confs) {
   * create consumer authorization configuration.
   * foreach ($consumer_confs as $consumer_type => $consumer_conf) {.
   *
   * @FIXME: Function does not exist
   * $consumer_obj = ldap_authorization_get_consumer_object($consumer_type);
   * $consumer_conf_admin = new LdapAuthorizationConsumerConfAdmin($consumer_obj, TRUE);
   * foreach ($consumer_conf as $property_name => $property_value) {
   * $consumer_conf_admin->{$property_name} = $property_value;
   * }
   * foreach ($consumer_conf_admin->mappings as $i => $mapping) {
   * $mappings = $consumer_obj->normalizeMappings(
   * array(
   * array($mapping['from'], $mapping['user_entered'])
   * )
   * , FALSE);
   * $consumer_conf_admin->mappings[$i] = $mappings[0];
   * }
   * $consumer_conf_admin->save();
   * }
   * }
   */
  public function ldapUserIsAuthmapped($username) {
    $externalauth = \Drupal::service('externalauth.externalauth');
    $authmaps = $externalauth->load($username, 'ldap_user');
    // @FIXME: Wrong return values
    return ($authmaps && in_array('ldap_user', array_keys($authmaps)));
  }

  /**
   *
   */
  public function drupalLdapUpdateUser($edit = array(), $ldap_authenticated = FALSE, $user) {
    if (count($edit)) {
      // FIXME:
      // $user = user_save($user, $edit);.
    }
    if ($ldap_authenticated) {
      // FIXME: see above authmaps
      // user_set_authmaps($user, array('authname_ldap_user' => $user->name));.
    }
    return $user;
  }

  /**
   * From http://www.midwesternmac.com/blogs/jeff-geerling/programmatically-adding-roles.
   */
  public function removeRoleFromUser($user, $role_name) {

    if (is_numeric($user)) {
      $user = user_load($user);
    }
    $key = array_search($role_name, $user->roles);
    if ($key == TRUE) {
      // Get the rid from the roles table.
      $roles = user_roles(TRUE);
      $rid = array_search($role_name, $roles);
      if ($rid != FALSE) {
        // Make a copy of the roles array, without the deleted one.
        $new_roles = array();
        foreach ($user->roles as $id => $name) {
          if ($id != $rid) {
            $new_roles[$id] = $name;
          }
        }
        // @FIXME user_save($user, array('roles' => $new_roles));
      }
    }
  }

  /**
   *
   */
  public function userByNameFlushingCache($name) {
    $user = user_load_by_name($name);
    // Clear user cache.
    $users = user_load_multiple(array($user->uid), array(), TRUE);
    $user = $users[$user->uid];
    return $user;
  }

  /**
   * Set variable with fake test data.
   *
   * @param string $test_ldap_id
   *   eg. 'hogwarts'.
   * @param string $test_ldap_type
   *   e.g. openLdap, openLdapTest1, etc.
   *
   * @parma string $sid where fake data is stored. e.g. 'default',
   */
  public function populateFakeLdapServerData($test_ldap_id, $sid = 'default') {

    // Read csvs into key/value array
    // create fake ldap data array.
    $clones = empty($this->data['ldap_servers'][$sid]['clones']) ? FALSE : $this->data['ldap_servers'][$sid]['clones'];
    $server_properties = $this->data['ldap_servers'][$sid]['properties'];
    $this->getCsvLdapData($test_ldap_id);
    foreach ($this->csvTables['users'] as $guid => $user) {
      $dn = 'cn=' . $user['cn'] . ',' . $this->csvTables['conf'][$test_ldap_id]['userbasedn'];
      $this->csvTables['users'][$guid]['dn'] = $dn;
      $attributes = $this->generateUserLDAPAttributes($test_ldap_id, $user);
      $this->addLDAPUserToLDAPArraysFromAttributes(
        $user,
        $sid,
        $dn,
        $attributes,
        $server_properties['ldap_type'],
        $server_properties['user_attr']
      );
    }

    if ($clones) {
      $clonable_user = $this->csvTables['users'][101];
      for ($i = 0; $i < $clones; $i++) {
        $user = $clonable_user;
        $cn = "clone" . $i;
        $dn = 'cn=' . $cn . ',' . $this->csvTables['conf'][$test_ldap_id]['userbasedn'];
        $user['cn'] = $cn;
        $user['dn'] = $dn;
        $user['uid'] = 20 + $i;
        $user['guid'] = 120 + $i;
        $user['lname'] = $user['lname'] . "_$i";
        $attributes = $this->generateUserLDAPAttributes($test_ldap_id, $user);
        $this->addLDAPUserToLDAPArraysFromAttributes(
          $user,
          $sid,
          $dn,
          $attributes,
          $server_properties['ldap_type'],
          $server_properties['user_attr']
        );
      }
    }

    foreach ($this->csvTables['groups'] as $guid => $group) {
      $dn = 'cn=' . $group['cn'] . ',' . $this->csvTables['conf'][$test_ldap_id]['groupbasedn'];
      $this->csvTables['groups'][$guid]['dn'] = $dn;
      $attributes = array(
        'cn' => array(
          0 => $group['cn'],
          'count' => 1,
        ),
        'gid' => array(
          0 => $group['gid'],
          'count' => 1,
        ),
        'guid' => array(
          0 => $guid,
          'count' => 1,
        ),
      );

      if ($server_properties['groupMembershipsAttr']) {
        $membershipAttr = $server_properties['groupMembershipsAttr'];
        foreach ($this->csvTables['memberships'] as $membership_id => $membership) {
          if ($membership['gid'] == $group['gid']) {
            $member_guid = $membership['member_guid'];
            if (isset($this->csvTables['users'][$member_guid])) {
              $member = $this->csvTables['users'][$member_guid];
            }
            elseif (isset($this->csvTables['groups'][$member_guid])) {
              $member = $this->csvTables['groups'][$member_guid];
            }
            if ($server_properties['groupMembershipsAttrMatchingUserAttr'] == 'dn') {
              $attributes[$server_properties['groupMembershipsAttr']][] = $member['dn'];
            }
            else {
              $attributes[$server_properties['groupMembershipsAttr']][] = $member['attr'][$membershipAttr][0];
            }
          }
        }
        $attributes[$membershipAttr]['count'] = count($attributes[$membershipAttr]);

      }
      // Need to figure out if memberOf type attribute is desired and populate it.
      $this->data['ldap_servers_by_guid'][$sid][$group['guid']]['attr'] = $attributes;
      $this->data['ldap_servers_by_guid'][$sid][$group['guid']]['dn'] = $dn;
      $this->data['ldap_servers'][$sid]['groups'][$dn]['attr'] = $attributes;
      $this->ldapData['ldap_servers'][$sid][$dn] = $attributes;

    }
    if ($server_properties['groupUserMembershipsAttrExists']) {
      $member_attr = $server_properties['groupUserMembershipsAttr'];
      foreach ($this->csvTables['memberships'] as $gid => $membership) {
        $group_dn = $this->data['ldap_servers_by_guid'][$sid][$membership['group_guid']]['dn'];
        $user_dn = $this->data['ldap_servers_by_guid'][$sid][$membership['member_guid']]['dn'];
        $this->ldapData['ldap_servers'][$sid][$user_dn][$member_attr][] = $group_dn;
        if (isset($this->ldapData['ldap_servers'][$sid][$user_dn][$member_attr]['count'])) {
          unset($this->ldapData['ldap_servers'][$sid][$user_dn][$member_attr]['count']);
        }
        $this->ldapData['ldap_servers'][$sid][$user_dn][$member_attr]['count'] =
        count($this->ldapData['ldap_servers'][$sid][$user_dn][$member_attr]);
      }
    }

    $this->data['ldap_servers'][$sid]['ldap'] = $this->ldapData['ldap_servers'][$sid];
    $this->data['ldap_servers'][$sid]['csv'] = $this->csvTables;
    // @FIXME
    // variable_set('ldap_test_server__' . $sid, $this->data['ldap_servers'][$sid]);
    // $current_sids = variable_get('ldap_test_servers', array());
    // $current_sids[] = $sid;
    // variable_set('ldap_test_servers', array_unique($current_sids));
  }

  /**
   *
   */
  public function generateUserLDAPAttributes($test_ldap_id, $user) {
    $attributes = array(
      'cn' => array(
        0 => $user['cn'],
        'count' => 1,
      ),
      'mail' => array(
        0 => $user['cn'] . '@' . $this->csvTables['conf'][$test_ldap_id]['mailhostname'],
        'count' => 1,
      ),
      'uid' => array(
        0 => $user['uid'],
        'count' => 1,
      ),
      'guid' => array(
        0 => $user['guid'],
        'count' => 1,
      ),
      'sn' => array(
        0 => $user['lname'],
        'count' => 1,
      ),
      'givenname' => array(
        0 => $user['fname'],
        'count' => 1,
      ),
      'house' => array(
        0 => $user['house'],
        'count' => 1,
      ),
      'department' => array(
        0 => $user['department'],
        'count' => 1,
      ),
      'faculty' => array(
        0 => (int) (boolean) $user['faculty'],
        'count' => 1,
      ),
      'staff' => array(
        0 => (int) (boolean) $user['staff'],
        'count' => 1,
      ),
      'student' => array(
        0 => (int) (boolean) $user['student'],
        'count' => 1,
      ),
      'gpa' => array(
        0 => $user['gpa'],
        'count' => 1,
      ),
      'probation' => array(
        0 => (int) (boolean) $user['probation'],
        'count' => 1,
      ),
      'password'  => array(
        0 => 'goodpwd',
        'count' => 1,
      ),
    );
    return $attributes;
  }

  /**
   *
   */
  public function addLDAPUserToLDAPArraysFromAttributes($user, $sid, $dn, $attributes, $ldap_type, $user_attr) {

    if ($ldap_type == 'activedirectory') {
      $attributes[$user_attr] = array(0 => $user['cn'], 'count' => 1);
      $attributes['distinguishedname'] = array(0 => $dn, 'count' => 1);
    }
    elseif ($ldap_type == 'openldap') {

    }

    $this->data['ldap_servers'][$sid]['users'][$dn]['attr'] = $attributes;
    $this->data['ldap_servers_by_guid'][$sid][$user['guid']]['attr'] = $attributes;
    $this->data['ldap_servers_by_guid'][$sid][$user['guid']]['dn'] = $dn;
    $this->ldapData['ldap_servers'][$sid][$dn] = $attributes;
    $this->ldapData['ldap_servers'][$sid][$dn]['count'] = count($attributes);
  }

  /**
   *
   */
  public function getCsvLdapData($test_ldap_id) {
    foreach (array('groups', 'users', 'memberships', 'conf') as $type) {
      $path = drupal_get_path('module', 'ldap_test') . '/test_ldap/' . $test_ldap_id . '/' . $type . '.csv';
      $this->csvTables[$type] = $this->parseCsv($path);
    }
  }

  /**
   *
   */
  public function parseCsv($filepath) {
    $row = 1;
    $table = array();
    if (($handle = fopen($filepath, "r")) !== FALSE) {
      while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
        if (count($data) > 1) {
          $table[] = $data;
        }
      }
      fclose($handle);
    }

    $table_associative = array();
    $headings = array_shift($table);
    foreach ($table as $i => $row) {
      $row_id = $row[0];
      foreach ($row as $j => $item) {
        $table_associative[$row_id][$headings[$j]] = $item;
      }
    }

    return $table_associative;

  }

  /**
   *
   */
  public function ldap_test_ldap_authentication_data() {

    $auth_conf = new LdapAuthenticationConfAdmin();

    $conf['default'] = array(
      'sids' => array('activedirectory1' => 'activedirectory1'),
      'authenticationMode' => LdapAuthenticationConf::$mode_mixed,
      'emailOption' => LdapAuthenticationConf::$emailFieldDisable,
      'emailUpdate' => LdapAuthenticationConf::$emailUpdateOnLdapChangeDisable,
      'loginUIUsernameTxt' => 'Hogwarts Username',
      'loginUIPasswordTxt' => 'Hogwards LDAP Password',
      'ldapUserHelpLinkUrl' => 'https://passwords.hogwarts.edu/',
      'ldapUserHelpLinkText' => 'Hogwarts IT Password Support Page',
      'allowOnlyIfTextInDn' => NULL,
      'excludeIfTextInDn' => NULL,
      'excludeIfNoAuthorizations' => FALSE,
      'ssoEnabled' => FALSE,
    );

    $conf['MixedModeUserLogon'] = $conf['default'];

    $conf['MixedModeUserLogon3'] = $conf['default'];
    $conf['MixedModeUserLogon3']['sids'] = array('activedirectory1' => 'activedirectory1');

    $conf['ExclusiveModeUserLogon'] = $conf['default'];
    $conf['ExclusiveModeUserLogon']['authenticationMode'] = $auth_conf::$mode_exclusive;

    $conf['SSOUserLogon'] = $conf['default'];
    $conf['SSOUserLogon']['authenticationMode'] = $auth_conf::$mode_exclusive;
    $conf['SSOUserLogon']['ssoEnabled'] = TRUE;
    $conf['SSOUserLogon']['ssoRemoteUserStripDomainName'] = FALSE;
    // -- 0, 3600, 86400, 604800, 2592000, 31536000, 315360000.
    $conf['SSOUserLogon']['cookieExpire'] = 3600;
    // 'mod_auth_kerb'.
    $conf['SSOUserLogon']['ldapImplementation'] = 'mod_auth_sspi';

    $conf['ExclusiveModeUserLogon3'] = $conf['default'];
    $conf['ExclusiveModeUserLogon3']['sids'] = array('activedirectory1' => 'activedirectory1');
    $conf['ExclusiveModeUserLogon3']['authenticationMode'] = $auth_conf::$mode_exclusive;

    $conf['WL1'] = $conf['default'];
    $conf['WL1']['authenticationMode'] = $auth_conf::$mode_exclusive;

    $conf['WL3'] = $conf['default'];
    $conf['WL3']['sids'] = array('activedirectory1' => 'activedirectory1');
    $conf['WL3']['authenticationMode'] = $auth_conf::$mode_exclusive;

    // Single sign on tests.
    $conf['MixedModeUserLogonSSO'] = $conf['MixedModeUserLogon'];
    $conf['MixedModeUserLogonSSO']['ssoRemoteUserStripDomainName'] = FALSE;
    $conf['MixedModeUserLogonSSO']['seamlessLogin'] = TRUE;
    $conf['MixedModeUserLogonSSO']['ldapImplementation'] = 'mod_auth_sspi';
    $conf['MixedModeUserLogonSSO']['cookieExpire'] = 3600;

    $conf['ExclusiveModeUserLogonSSO'] = $conf['ExclusiveModeUserLogon'];
    $conf['ExclusiveModeUserLogonSSO']['ssoRemoteUserStripDomainName'] = FALSE;
    $conf['ExclusiveModeUserLogonSSO']['seamlessLogin'] = FALSE;
    $conf['ExclusiveModeUserLogonSSO']['ldapImplementation'] = 'mod_auth_sspi';
    $conf['ExclusiveModeUserLogonSSO']['cookieExpire'] = 3600;

    return $conf;

  }

  /**
   * Activedirectory is default Active Directory server config .
   */
  public function ldap_test_ldap_servers_data() {

    $servers['ldapauthor1']['properties']  = array(
      'sid' => 'openldap1',
      'name'  => 'Test LDAP Server LDAP Authorization' ,
      'inDatabase' => TRUE,
      'status'  => 1,
      'ldap_type'  => 'openldap',
      'address'  => 'ldap.hogwarts.edu',
      'port'  => 389,
      'tls'  => FALSE,
      'bind_method' => Server::$bindMethodServiceAccount,
      'basedn'  => array(
        'dc=hogwarts,dc=edu',
      ),
      'binddn'  => 'cn=service-account,ou=people,dc=hogwarts,dc=edu',
      'bindpw' => 'goodpwd',
      'user_dn_expression' => NULL,
      'user_attr'  => 'cn',
      'mail_attr'  => 'mail',
      'mail_template'  => NULL,
      'unique_persistent_attr' => 'guid',
      'groupObjectClass' => 'groupofnames',
      'groupUserMembershipsAttrExists' => FALSE,
      'groupUserMembershipsAttr' => NULL,
      'groupMembershipsAttr' => 'member',
      'groupMembershipsAttrMatchingUserAttr' => 'dn',
      'search_pagination' => 0,
      'searchPageSize' => NULL,
    );

    $conf['openldap1']['properties']  = array(
      'sid' => 'openldap1',
      'name'  => 'Test Open LDAP' ,
      'inDatabase' => TRUE,
      'status'  => 1,
      'ldap_type'  => 'openldap',
      'address'  => 'ldap.hogwarts.edu',
      'port'  => 389,
      'tls'  => FALSE,
      'bind_method' => Server::$bindMethodServiceAccount,
      'basedn'  => array(
        'dc=hogwarts,dc=edu',
      ),
      'binddn'  => 'cn=service-account,ou=people,dc=hogwarts,dc=edu',
      'bindpw' => 'goodpwd',
      'user_dn_expression' => NULL,
      'user_attr'  => 'cn',
      'mail_attr'  => 'mail',
      'mail_template'  => NULL,
      'unique_persistent_attr' => 'guid',
      'unique_persistent_attr_binary' => FALSE,
      'groupObjectClass' => 'groupofnames',
      'groupUserMembershipsAttrExists' => FALSE,
      'groupUserMembershipsAttr' => NULL,
      'groupMembershipsAttr' => 'member',
      'groupMembershipsAttrMatchingUserAttr' => 'dn',
      'search_pagination' => 0,
      'searchPageSize' => NULL,
    );

    $conf['openldap1']['methodResponses']['connect'] = self::LDAP_SUCCESS;

    $conf['openldap1']['search_results'] = array();

    $conf['openldap1']['search_results']['(&(objectClass=group)(|(member=cn=gryffindor,ou=groups,dc=hogwarts,dc=edu)(member=cn=students,ou=groups,dc=hogwarts,dc=edu)(member=cn=honors students,ou=groups,dc=hogwarts,dc=edu)))']['dc=hogwarts,dc=edu'] = array(
      0 => array('count' => 1, 'dn' => 'cn=users,ou=groups,dc=hogwarts,dc=edu'),
      'count' => 1,
    );

    $conf['openldap1']['search_results']['(cn=hpotter)']['dc=hogwarts,dc=edu'] = array(
      0 => array(
        'count' => 1,
        'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
        'FULLENTRY' => TRUE,
      ),
      'count' => 1,
    );

    $conf['openldap1']['search_results']['(cn=hpotter)']['dc=hogwarts,dc=edu'] = array(
      0 => array(
        'count' => 1,
        'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
        'FULLENTRY' => TRUE,
      ),
      'count' => 1,
    );

    $conf['openldap1']['search_results']['(cn=hpotter-granger)']['dc=hogwarts,dc=edu'] = array(
      0 => array(
        'count' => 1,
        'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
        'FULLENTRY' => TRUE,
      ),
      'count' => 1,
    );

    $conf['openldap1']['search_results']['(cn=ssnape)']['dc=hogwarts,dc=edu'] = array(
      0 => array(
        'count' => 1,
        'dn' => 'cn=ssnape,ou=people,dc=hogwarts,dc=edu',
        'FULLENTRY' => TRUE,
      ),
      'count' => 1,
    );

    $conf['openldap1']['search_results']['(cn=adumbledore)']['dc=hogwarts,dc=edu'] = array(
      0 => array(
        'count' => 1,
        'dn' => 'cn=adumbledore,ou=people,dc=hogwarts,dc=edu',
        'FULLENTRY' => TRUE,
      ),
      'count' => 1,
    );

    $conf['openldap1']['search_results']['(&(objectClass=groupofnames)(member=cn=hpotter,ou=people,dc=hogwarts,dc=edu))']['dc=hogwarts,dc=edu'] = array(
      0 => array('count' => 1, 'dn' => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu'),
      1 => array('count' => 1, 'dn' => 'cn=students,ou=groups,dc=hogwarts,dc=edu'),
      2 => array('count' => 1, 'dn' => 'cn=honors students,ou=groups,dc=hogwarts,dc=edu'),
      'count' => 3,
    );

    $conf['openldap1']['search_results']['(&(objectClass=groupofnames)(|(member=cn=gryffindor,ou=groups,dc=hogwarts,dc=edu)(member=cn=students,ou=groups,dc=hogwarts,dc=edu)(member=cn=honors students,ou=groups,dc=hogwarts,dc=edu)))']['dc=hogwarts,dc=edu'] = array(
      0 => array('count' => 1, 'dn' => 'cn=users,ou=groups,dc=hogwarts,dc=edu'),
      'count' => 1,
    );

    $conf['activedirectory1']['properties']  = array(
      'sid' => 'activedirectory1',
      'name'  => 'Test Active Directory LDAP' ,
      'inDatabase' => TRUE,
      'status'  => 1,
      'ldap_type'  => 'activedirectory',
      'address'  => 'ldap.hogwarts.edu',
      'port'  => 389,
      'tls'  => FALSE,
      'bind_method' => Server::$bindMethodServiceAccount,
      'basedn'  => array(
        'dc=hogwarts,dc=edu',
      ),
      'binddn'  => 'cn=service-account,ou=people,dc=hogwarts,dc=edu',
      'bindpw' => 'goodpwd',
      'user_dn_expression' => NULL,
      'user_attr'  => 'samaccountname',
      'mail_attr'  => 'mail',
      'mail_template'  => NULL,
      'unique_persistent_attr' => 'guid',
      'unique_persistent_attr_binary' => FALSE,
      'groupNested' => 0,
      'groupObjectClass' => 'group',
      'groupUserMembershipsAttrExists' => TRUE,
      'groupUserMembershipsAttr' => 'memberof',
      'groupMembershipsAttr' => 'member',
      'groupMembershipsAttrMatchingUserAttr' => 'dn',
      'search_pagination' => 0,
      'searchPageSize' => NULL,
    );

    $conf['activedirectory1']['methodResponses']['connect'] = self::LDAP_SUCCESS;
    $conf['activedirectory1']['clones'] = LdapWebTestBase::$userOrphanCloneCount;

    $conf['activedirectory1']['search_results'] = array();

    $conf['activedirectory1']['search_results']['(&(objectClass=group)(member=cn=hpotter,ou=people,dc=hogwarts,dc=edu))']['dc=hogwarts,dc=edu'] = array(
      0 => array('count' => 1, 'dn' => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu'),
      1 => array('count' => 1, 'dn' => 'cn=students,ou=groups,dc=hogwarts,dc=edu'),
      2 => array('count' => 1, 'dn' => 'cn=honors students,ou=groups,dc=hogwarts,dc=edu'),
      'count' => 3,
    );

    $conf['activedirectory1']['search_results']['(&(objectClass=group)(|(member=cn=gryffindor,ou=groups,dc=hogwarts,dc=edu)(member=cn=students,ou=groups,dc=hogwarts,dc=edu)(member=cn=honors students,ou=groups,dc=hogwarts,dc=edu)))']['dc=hogwarts,dc=edu'] = array(
      0 => array('count' => 1, 'dn' => 'cn=users,ou=groups,dc=hogwarts,dc=edu'),
      'count' => 1,
    );

    foreach (array('hpotter', 'hgrainger', 'ssnape', 'adumbledore') as $cn) {

      $conf['activedirectory1']['search_results']["(cn=$cn)"]['dc=hogwarts,dc=edu'] = array(
        0 => array(
          'count' => 1,
          'dn' => "cn=$cn,ou=people,dc=hogwarts,dc=edu",
          'FULLENTRY' => TRUE,
        ),
        'count' => 1,
      );

      $conf['activedirectory1']['search_results']["(samaccountname=$cn)"]['dc=hogwarts,dc=edu'] = array(
        0 => array(
          'count' => 1,
          'dn' => "cn=$cn,ou=people,dc=hogwarts,dc=edu",
          'FULLENTRY' => TRUE,
        ),
        'count' => 1,
      );

    }

    $conf['activedirectory1']['search_results']['(samaccountname=hpotter-granger)']['dc=hogwarts,dc=edu'] = array(
      0 => array(
        'count' => 1,
        'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
        'FULLENTRY' => TRUE,
      ),
      'count' => 1,
    );

    return $conf;
  }

  /**
   *
   */
  public function ldap_test_ldap_authorization_data() {

    $empty_mappings = array(
      'from' => '',
      'user_entered' => '',
      'normalized' => '',
      'simplified' => '',
      'valid' => '',
      'error_message' => '',
    );
    // Cant use constant OG_AUTHENTICATED_ROLE here.
    $OG_AUTHENTICATED_ROLE = 'member';
    $conf['og_group2']['og_group'] = array(

      'sid' => 'activedirectory1',
      'consumerType' => 'og_group',
      'consumerModule' => 'ldap_authorization_og_group',

      'description' => 'Hogwarts AD',
      'status' => 1,
      'onlyApplyToLdapAuthenticated' => 1,

      'mappings' => array(
        array(
          'from' => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'students',
          'normalized' => 'node:students:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => '',
          'valid' => '',
          'error_message' => '',
        ),
        array(
          'from' => 'cn=faculty,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'faculty',
          'normalized' => 'node:faculty:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => '',
          'valid' => '',
          'error_message' => '',
        ),
        array(
          'from' => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'gryffindor',
          'normalized' => 'node:gryffindor:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => '',
          'valid' => '',
          'error_message' => '',
        ),
        array(
          'from' => 'cn=users,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'users',
          'normalized' => 'node:users:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => '',
          'valid' => '',
          'error_message' => '',
        ),
      ),

      'useMappingsAsFilter' => 1,

      'syncOnLogon' => 1,

      'revokeLdapProvisioned' => 1,
      'createConsumerTargets' => 0,
      'regrantLdapProvisioned' => 1,

    );

    $conf['og_group15']['og_group'] = $conf['og_group2']['og_group'];
    $conf['og_group15']['og_group']['mappings'] = array(
      array(
        'from' => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
        'user_entered' => 'group-name=students,role-name=member',
        'simplified' => '',
        'valid' => '',
        'error_message' => '',
      ),
      array(
        'from' => 'cn=faculty,ou=groups,dc=hogwarts,dc=edu',
        'user_entered' => 'group-name=faculty,role-name=member',
        'simplified' => '',
        'valid' => '',
        'error_message' => '',
      ),
      array(
        'from' => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
        'user_entered' => 'group-name=gryffindor,role-name=member',
        'simplified' => '',
        'valid' => '',
        'error_message' => '',
      ),
      array(
        'from' => 'cn=users,ou=groups,dc=hogwarts,dc=edu',
        'user_entered' => 'group-name=users,role-name=member',
        'simplified' => '',
        'valid' => '',
        'error_message' => '',
      ),
    );

    $conf['drupal_role_default']['drupal_role'] = array(

      'sid' => 'activedirectory1',
      'consumerType' => 'drupal_role',
      'consumerModule' => 'ldap_authorization_drupal_role',

      'description' => 'Hogwarts AD',
      'status' => 1,
      'onlyApplyToLdapAuthenticated' => 1,

      'mappings' => array(
        array(
          'from' => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'students',
          'normalized' => 'students',
          'simplified' => 'students',
          'valid' => TRUE,
          'error_message' => '',
        ),
        array(
          'from' => 'cn=faculty,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'administrator',
          'normalized' => 'administrator',
          'simplified' => 'administrator',
          'valid' => TRUE,
          'error_message' => '',
        ),
        array(
          'from' => 'gryffindor',
          'user_entered' => 'gryffindor',
          'normalized' => 'gryffindor',
          'simplified' => 'gryffindor',
          'valid' => TRUE,
          'error_message' => '',
        ),
        array(
          'from' => 'cn=users,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'users',
          'normalized' => 'users',
          'simplified' => 'users',
          'valid' => TRUE,
          'error_message' => '',
        ),
      ),

      'useMappingsAsFilter' => 0,

      'syncOnLogon' => 1,

      'revokeLdapProvisioned' => 1,
      'createConsumerTargets' => 1,
      'regrantLdapProvisioned' => 1,
    );

    $conf['drupal_role_authentication_test']['drupal_role'] = array(
      'sid' => 'activedirectory1',
      'consumerType' => 'drupal_role',
      'consumerModule' => 'ldap_authorization_drupal_role',

      'description' => 'Hogwarts AD',
      'status' => 1,
      'onlyApplyToLdapAuthenticated' => 1,

      'mappings' => array(
        array(
          'from' => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'students',
          'normalized' => 'node:students:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => 'students',
          'valid' => TRUE,
          'error_message' => '',
        ),
        array(
          'from' => 'gryffindor',
          'user_entered' => 'gryffindor',
          'normalized' => 'node:gryffindor:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => 'gryffindor',
          'valid' => TRUE,
          'error_message' => '',
        ),
        array(
          'from' => 'cn=users,ou=groups,dc=hogwarts,dc=edu',
          'user_entered' => 'users',
          'normalized' => 'node:users:' . $OG_AUTHENTICATED_ROLE,
          'simplified' => 'users',
          'valid' => TRUE,
          'error_message' => '',
        ),
      ),

      'useMappingsAsFilter' => 1,

      'syncOnLogon' => 1,

      'revokeLdapProvisioned' => 1,
      'createConsumerTargets' => 1,
      'regrantLdapProvisioned' => 1,
    );

    return $conf;
  }

  /**
   *
   */
  public function ldap_test_ldap_user_data() {

    $conf['default']  = array(
      'drupalAcctProvisionServer' => 'activedirectory1',
      'ldapEntryProvisionServer' => LdapUserConf::$noServerSID,
      'drupalAcctProvisionTriggers' => array(
        LdapUserConf::$provisionDrupalUserOnUserUpdateCreate,
        LdapUserConf::$provisionDrupalUserOnAuthentication,
      ),
      'ldapEntryProvisionTriggers' => array(),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,
      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(),
      ),
      'orphanedCheckQty' => 50,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
    );

    $conf['ad_authentication'] = array(
      'drupalAcctProvisionServer' => 'activedirectory1',
      'ldapEntryProvisionServer' => LdapUserConf::$noServerSID,
      'drupalAcctProvisionTriggers' => array(
        LdapUserConf::$provisionDrupalUserOnUserUpdateCreate,
        LdapUserConf::$provisionDrupalUserOnAuthentication,
      ),
      'ldapEntryProvisionTriggers' => array(),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,
      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(),
      ),
      'orphanedCheckQty' => 50,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
    );

    $conf['ad_authorization'] = array(
      'drupalAcctProvisionServer' => 'ldapauthor1',
      'ldapEntryProvisionServer' => LdapUserConf::$noServerSID,
      'drupalAcctProvisionTriggers' => array(
        LdapUserConf::$provisionDrupalUserOnUserUpdateCreate,
        LdapUserConf::$provisionDrupalUserOnAuthentication,
      ),
      'ldapEntryProvisionTriggers' => array(),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,

      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(),
      ),
      'orphanedCheckQty' => 50,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
    );

    $conf['provisionToDrupal']  = array(
      'drupalAcctProvisionServer' => 'activedirectory1',
      'ldapEntryProvisionServer' => LdapUserConf::$noServerSID,
      'drupalAcctProvisionTriggers' => array(
        LdapUserConf::$provisionDrupalUserOnUserUpdateCreate,
        LdapUserConf::$provisionDrupalUserOnAuthentication,
      ),
      'ldapEntryProvisionTriggers' => array(),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,
      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(),
      ),
      'orphanedCheckQty' => 50,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
    );

    $conf['provisionToDrupalWithMappings']  = array(
      'drupalAcctProvisionServer' => 'activedirectory1',
      'ldapEntryProvisionServer' => LdapUserConf::$noServerSID,
      'drupalAcctProvisionTriggers' => array(
        LdapUserConf::$provisionDrupalUserOnUserUpdateCreate,
        LdapUserConf::$provisionDrupalUserOnAuthentication,
      ),
      'ldapEntryProvisionTriggers' => array(
        LdapUserConf::$provisionLdapEntryOnUserUpdateCreate,
      ),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,
      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(
          '[field.field_display_name]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[givenname] [sn]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '[field.field_display_name]',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateDrupalUser, LdapUserConf::$eventSyncToDrupalUser),
          ),
          '[field.field_lname]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[sn:0]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '[field.field_lname]',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateDrupalUser, LdapUserConf::$eventSyncToDrupalUser),
          ),
          '[field.field_fname]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[givenName]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '[field.field_fname]',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateDrupalUser, LdapUserConf::$eventSyncToDrupalUser),
          ),
          '[field.field_department]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => 'Physics',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '[field.field_department]',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateDrupalUser, LdapUserConf::$eventSyncToDrupalUser),
          ),
        ),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(),
      ),
      'orphanedCheckQty' => 50,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
    );

    $conf['provisionToLdap_activedirectory1']  = array(
      'drupalAcctProvisionServer' => LdapUserConf::$noServerSID,
      'ldapEntryProvisionServer' => 'activedirectory1',
      'drupalAcctProvisionTriggers' => array(),
      'ldapEntryProvisionTriggers' => array(
        LdapUserConf::$provisionLdapEntryOnUserUpdateCreate,
        LdapUserConf::$provisionLdapEntryOnUserDelete,
      ),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(
          '[dn]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[dn]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => 'cn=[property.name],ou=people,dc=hogwarts,dc=edu',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[cn]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[cn]',
            'user_attr' => '[property.name]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[displayname]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[displayname]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '[field.field_fname] [field.field_lname]',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[samaccountname]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[samaccountname]',
            'user_attr' => '[property.name]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry),
          ),
          '[sn]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[sn]',
            'user_attr' => '[field.field_lname]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[givenname]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[givenname]',
            'user_attr' => '[field.field_fname]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[guid]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[guid]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '151',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry),
          ),
          '[provisionsource]' => array(
            'sid' => 'activedirectory1',
            'ldap_attr' => '[provisionsource]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => 'drupal.hogwarts.edu',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry),
          ),
        ),
      ),
    );

    $conf['provisionToLdap_openldap1']  = array(
      'drupalAcctProvisionServer' => LdapUserConf::$noServerSID,
      'ldapEntryProvisionServer' => 'openldap1',
      'drupalAcctProvisionTriggers' => array(),
      'ldapEntryProvisionTriggers' => array(
        LdapUserConf::$provisionLdapEntryOnUserUpdateCreate,
        LdapUserConf::$provisionLdapEntryOnUserDelete,
      ),
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation'  => LdapUserConf::$accountCreationLdapBehaviour,
      'manualAccountConflict' => LdapUserConf::$manualAccountConflictShowOptionOnForm,
      'ldapUserSyncMappings' => array(
        LdapUserConf::$provisioningDirectionToDrupalUser => array(),
        LdapUserConf::$provisioningDirectionToLDAPEntry => array(
          '[dn]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[dn]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => 'cn=[property.name],ou=people,dc=hogwarts,dc=edu',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[displayname]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[displayname]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '[field.field_fname] [field.field_lname]',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[cn]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[cn]',
            'user_attr' => '[property.name]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry),
          ),
          '[sn]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[sn]',
            'user_attr' => '[field.field_lname]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[givenname]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[givenname]',
            'user_attr' => '[field.field_fname]',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
          ),
          '[guid]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[guid]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => '151',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry),
          ),
          '[provisionsource]' => array(
            'sid' => 'openldap1',
            'ldap_attr' => '[provisionsource]',
            'user_attr' => 'user_tokens',
            'convert' => 0,
            'direction' => LdapUserConf::$provisioningDirectionToLDAPEntry,
            'user_tokens' => 'drupal.hogwarts.edu',
            'config_module' => 'ldap_user',
            'sync_module' => 'ldap_user',
            'enabled' => 1,
            'prov_events' => array(LdapUserConf::$eventCreateLdapEntry),
          ),
        ),
      ),
    );

    return $conf;

  }

}
