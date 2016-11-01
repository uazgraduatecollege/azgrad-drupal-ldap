<?php

namespace Drupal\ldap_servers\tests;

use Drupal\ldap_servers\TokenFunctions;

/**
 * Tests covering ldap_server module.
 *
 * @group ldap
 */
class ServerAPITests extends LdapWebTestBase {

  use TokenFunctions;

  /**
   * {@inheritdoc}
   */
  public static function getInfo() {
    return array(
      'name' => 'LDAP Servers Tests',
      'description' => 'Test ldap servers.  Servers module is primarily a storage
        tool for ldap server configuration, so most of testing is just form and db testing.
        there are some api like functions that are also tested.',
      'group' => 'ldap',
    );
  }

  /**
   * {@inheritdoc}
   */
  public function __construct($test_id = NULL) {
    parent::__construct($test_id);
  }

  protected $ldap_test_data;

  public static $modules = array('ldap_servers');

  /**
   * Create one or more server configurations in such as way
   *  that this setUp can be a prerequisite for ldap_authentication and ldap_authorization.
   *    * Function setUp() {
   * parent::setUp(array('ldap_test'));
   * variable_set('ldap_simpletest', 2);
   * }
   *    * function tearDown() {
   * parent::tearDown();
   * variable_del('ldap_help_watchdog_detail');
   * variable_del('ldap_simpletest');
   * }.
   */
  public function testApiFunctions() {

    return;

    // The tests below are disabled due to significant structural mismatch.
    // , 'activedirectory1'.
    foreach (array('openldap1', 'activedirectory1') as $sid) {
      $ldap_type = ($sid == 'openldap1') ? 'Open Ldap' : 'Active Directory';
      $this->prepTestData('hogwarts', array($sid));

      $group = "ldap_servers: functions: $ldap_type";
      // @FIXME $test_data = variable_get('ldap_test_server__' . $sid, array());
      $ldap_server = TestServer::getLdapServerObjects($sid, NULL, TRUE);

      // Check against csv data rather than ldap array to make sure csv to ldap conversion is correct.
      // @FIXME: Remove line below when fixed above
      $test_data['csv']['users']['101'] = 'temp';
      $user_csv_entry = $test_data['csv']['users']['101'];
      $user_dn = $user_csv_entry['dn'];
      $user_cn = $user_csv_entry['cn'];
      $user_ldap_entry = $test_data['ldap'][$user_dn];

      $username = $ldap_server->userUsernameFromLdapEntry($user_ldap_entry);
      $this->assertTrue($username == $user_csv_entry['cn'], 'LdapServer::userUsernameFromLdapEntry works when LdapServer::user_attr attribute used', $group);

      $bogus_ldap_entry = array();
      $username = $ldap_server->userUsernameFromLdapEntry($bogus_ldap_entry);
      $this->assertTrue($username === FALSE, 'LdapServer::userUsernameFromLdapEntry fails correctly', $group);

      $username = $ldap_server->userUsernameFromDn($user_dn);
      $this->assertTrue($username == $user_cn, 'LdapServer::userUsernameFromDn works when LdapServer::user_attr attribute used', $group);

      $username = $ldap_server->userUsernameFromDn('bogus dn');
      $this->assertTrue($username === FALSE, 'LdapServer::userUsernameFromDn fails correctly', $group);

      $desired = array();
      $desired[0] = array(
        0 => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
        1 => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
        2 => 'cn=honors students,ou=groups,dc=hogwarts,dc=edu',
      );
      $desired[1] = array_merge($desired[0], array('cn=users,ou=groups,dc=hogwarts,dc=edu'));

      foreach (array(0, 1) as $nested) {

        $nested_display = ($nested) ? 'nested' : 'not nested';
        $desired_count = ($nested) ? 4 : 3;
        $ldap_module_user_entry = array('attr' => $user_ldap_entry, 'dn' => $user_dn);
        $groups_desired = $desired[$nested];

        $suffix = ",desired=$desired_count, nested=" . (boolean) $nested;

        // Test parent function groupMembershipsFromUser.
        $groups = $ldap_server->groupMembershipsFromUser($ldap_module_user_entry, 'group_dns', $nested);
        $count = count($groups);
        $diff1 = array_diff($groups_desired, $groups);
        $diff2 = array_diff($groups, $groups_desired);
        $pass = (count($diff1) == 0 && count($diff2) == 0 && $count == $desired_count);
        $this->assertTrue($pass, "LdapServer::groupMembershipsFromUser nested=$nested", $group . $suffix);
        if (!$pass) {
          debug('groupMembershipsFromUser');debug($groups);  debug($diff1);  debug($diff2);  debug($groups_desired);
        }

        // Test parent groupUserMembershipsFromUserAttr, for openldap should be false, for ad should work.
        $groups = $ldap_server->groupUserMembershipsFromUserAttr($ldap_module_user_entry, $nested);
        $count = is_array($groups) ? count($groups) : $count;
        $pass = $count === FALSE;
        if ($sid == 'openldap1') {
          $pass = ($groups === FALSE);
        }
        else {
          $pass = (count($diff1) == 0 && count($diff2) == 0 && $count == $desired_count);
        }
        $this->assertTrue($pass, "LdapServer::groupUserMembershipsFromUserAttr $nested_display, $ldap_type, is false because not configured", $group . $suffix);
        if (!$pass) {
          debug('groupUserMembershipsFromUserAttr');debug($groups);  debug($diff1);  debug($diff2);
        }

        $groups = $ldap_server->groupUserMembershipsFromEntry($ldap_module_user_entry, $nested);
        $count = count($groups);
        $diff1 = array_diff($groups_desired, $groups);
        $diff2 = array_diff($groups, $groups_desired);
        $pass = (count($diff1) == 0 && count($diff2) == 0 && $count == $desired_count);
        $this->assertTrue($pass, "LdapServer::groupUserMembershipsFromEntry $nested_display works", $group . $suffix);
        if (!$pass) {
          debug('groupUserMembershipsFromEntry'); debug($groups);  debug($diff1);  debug($diff2);  debug($groups_desired);
        }
      }
    }
  }

  /**
   *
   */
  public function testInstall() {

    return;

    // Unclear what this test event attemps to show. Disabling until ported.
    $install_tables = array('ldap_servers');
    // disable, uninstall, and enable/install module.
    $modules = array($this->module_name);
    $module_installer = ModuleInstaller();
    $ldap_module_uninstall_sequence = array('ldap_authentication', 'ldap_test', 'ldap_user', 'ldap_group', 'ldap_servers');
    // Uninstall dependent modules.
    $module_installer->uninstall($modules, TRUE);
    // Uninstall dependent modules.
    $module_installer->install($modules, TRUE);
    foreach ($install_tables as $table) {
      $this->assertTrue(db_table_exists($table), $table . ' table creates', $group);
    }

    // Unistall dependent modules.
    $module_installer->uninstall($modules, TRUE);
    foreach ($install_tables as $table) {
      $this->assertFalse(db_table_exists($table), $table . ' table removed', $group);
    }

    // Test tokens, see http://drupal.org/node/1245736
    $ldap_entry = array(
      'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
      'mail' => array(0 => 'hpotter@hogwarts.edu', 'count' => 1),
      'sAMAccountName' => array(0 => 'hpotter', 'count' => 1),
      'house' => array(0 => 'Gryffindor', 1 => 'Privet Drive', 'count' => 2),
      'guid' => array(0 => 'sdafsdfsdf', 'count' => 1),
      'count' => 3,
    );

    $this->ldapTestId = 'ldap_server.tokens';

    $dn = $this->tokenReplace($ldap_entry, '[dn]');
    $this->assertTrue($dn == $ldap_entry['dn'], t('[dn] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $house0 = $this->tokenReplace($ldap_entry, '[house:0]');
    $this->assertTrue($house0 == $ldap_entry['house'][0], t("[house:0] token worked ($house0) on $this->tokenReplace()."), $this->ldapTestId);

    $mixed = $this->tokenReplace($ldap_entry, 'thisold[house:0]');
    $this->assertTrue($mixed == 'thisold' . $ldap_entry['house'][0], t("thisold[house:0] token worked ($mixed) on $this->tokenReplace()."), $this->ldapTestId);

    $compound = $this->tokenReplace($ldap_entry, '[samaccountname:0][house:0]');
    $this->assertTrue($compound == $ldap_entry['sAMAccountName'][0] . $ldap_entry['house'][0], t("[samaccountname:0][house:0] compound token worked ($mixed) on $this->tokenReplace()."), $this->ldapTestId);

    $literalvalue = $this->tokenReplace($ldap_entry, 'literalvalue');
    $this->assertTrue($literalvalue == 'literalvalue', t("'literalvalue' token worked ($literalvalue) on $this->tokenReplace()."), $this->ldapTestId);

    $house0 = $this->tokenReplace($ldap_entry, '[house]');
    $this->assertTrue($house0 == $ldap_entry['house'][0], t("[house] token worked ($house0) on $this->tokenReplace()."), $this->ldapTestId);

    $house1 = $this->tokenReplace($ldap_entry, '[house:last]');
    $this->assertTrue($house1 == $ldap_entry['house'][1], t('[house:last] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $sAMAccountName = $this->tokenReplace($ldap_entry, '[samaccountname:0]');
    $this->assertTrue($sAMAccountName == $ldap_entry['sAMAccountName'][0], t('[samaccountname:0] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $sAMAccountNameMixedCase = $this->tokenReplace($ldap_entry, '[sAMAccountName:0]');
    $this->assertTrue($sAMAccountNameMixedCase == $ldap_entry['sAMAccountName'][0], t('[sAMAccountName:0] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $sAMAccountName2 = $this->tokenReplace($ldap_entry, '[samaccountname]');
    $this->assertTrue($sAMAccountName2 == $ldap_entry['sAMAccountName'][0], t('[samaccountname] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $sAMAccountName3 = $this->tokenReplace($ldap_entry, '[sAMAccountName]');
    $this->assertTrue($sAMAccountName2 == $ldap_entry['sAMAccountName'][0], t('[sAMAccountName] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $base64encode = $this->tokenReplace($ldap_entry, '[guid;base64_encode]');
    $this->assertTrue($base64encode == base64_encode($ldap_entry['guid'][0]), t('[guid;base64_encode] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $bin2hex = $this->tokenReplace($ldap_entry, '[guid;bin2hex]');
    $this->assertTrue($bin2hex == bin2hex($ldap_entry['guid'][0]), t('[guid;bin2hex] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $msguid = $this->tokenReplace($ldap_entry, '[guid;msguid]');
    $this->assertTrue($msguid == ldap_servers_msguid($ldap_entry['guid'][0]), t('[guid;msguid] token worked on $this->tokenReplace().'), $this->ldapTestId);

    $binary = $this->tokenReplace($ldap_entry, '[guid;binary]');
    $this->assertTrue($binary == ldap_servers_binary($ldap_entry['guid'][0]), t('[guid;binary] token worked on $this->tokenReplace().'), $this->ldapTestId);

    /**
     * @todo test tokens for 'user_account'
     *
     * $account = new stdClass();
     * $account->
     * $this->tokenReplace($account, '[property.name]', 'user_account');
     */

    module_enable($modules, TRUE);
  }

}
