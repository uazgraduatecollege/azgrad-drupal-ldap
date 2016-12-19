<?php

namespace Drupal\ldap_user\Tests;

use Drupal\ldap_servers\tests\LdapWebTestBase;
use Drupal\ldap_user\LdapUserConf;

/**
 * UI tests for ldap_user.
 *
 * @group ldap_user
 */
class LdapWebUserUITests extends LdapWebTestBase {

  /**
   *
   */
  public static function getInfo() {
    return array(
      'name' => 'LDAP User User Interface',
      'description' => 'Test ldap user admin interface.',
      'group' => 'LDAP User',
    );
  }

  public $module_name = 'ldap_user';
  protected $ldap_test_data;

  public static $modules = array('ldap_servers', 'ldap_authentication', 'ldap_authorization', 'ldap_user');


  /**
   * Create one or more server configurations in such as way
   *  that this setUp can be a prerequisite for ldap_authentication and ldap_authorization.
   *    * Function setUp() {
   * parent::setUp(array('ldap_user', 'ldap_test'));
   * // @FIXME
   * // // @FIXME
   * // // This looks like another module's variable. You'll need to rewrite this call
   * // // to ensure that it uses the correct configuration object.
   * // variable_set('ldap_simpletest', 2);
   *    * }
   *    * function tearDown() {
   * parent::tearDown();
   * // @FIXME
   * // // @FIXME
   * // // This looks like another module's variable. You'll need to rewrite this call
   * // // to ensure that it uses the correct configuration object.
   * // variable_del('ldap_help_watchdog_detail');
   *    * // @FIXME
   * // // @FIXME
   * // // This looks like another module's variable. You'll need to rewrite this call
   * // // to ensure that it uses the correct configuration object.
   * // variable_del('ldap_simpletest');
   *    * }.
   */

  /**
   * Make sure user admin interface works.  (its a beast)
   */
  public function testUI() {

    // Just to give warning if setup doesn't succeed.  may want to take these out at some point.
    // @FIXME
    // // @FIXME
    // // This looks like another module's variable. You'll need to rewrite this call
    // // to ensure that it uses the correct configuration object.
    // $setup_success = (
    //         module_exists('ldap_user') &&
    //         module_exists('ldap_servers') &&
    //         (variable_get('ldap_simpletest', 2) > 0)
    //       );.
    $this->assertTrue($setup_success, ' ldap_user setup successful', $this->testId('user interface tests'));

    $sids = array('activedirectory1');
    $this->prepTestData('hogwarts', $sids, 'provisionToDrupal', 'default');

    $this->privileged_user = $this->drupalCreateUser(array(
      'administer site configuration',
      'administer users',
    ));

    $this->drupalLogin($this->privileged_user);

    $ldap_user_conf = new LdapUserConf();
    $this->drupalGet('admin/config/people/ldap/user');

    // Populate the field settings with new settings.
    $sid = 'activedirectory1';

    $edit_direct_map = array(

      'manualAccountConflict' => LdapUserConf::$manualAccountConflictLdapAssociate,
      'drupalAcctProvisionServer' => $sid,
      'userConflictResolve' => LdapUserConf::$userConflictLog,
      'acctCreation' => LdapUserConf::$accountCreationLdapBehaviour,
      'orphanedDrupalAcctBehavior' => 'ldap_user_orphan_email',
      'orphanedCheckQty' => '50',
      'ldapEntryProvisionServer' => $sid,
    );
    $edit = $edit_direct_map + array(
      'drupalAcctProvisionTriggers[' . LdapUserConf::$provisionDrupalUserOnAuthentication . ']' => TRUE,
      'drupalAcctProvisionTriggers[' . LdapUserConf::$provisionDrupalUserOnUserUpdateCreate . ']' => TRUE,

      '1__sm__ldap_attr__6' => '[sn]',
      '1__sm__convert__6' => FALSE,
      '1__sm__user_attr__6' => '[field.field_lname]',
      '1__sm__1__6' => TRUE,
      '1__sm__2__6' => TRUE,

      '1__sm__ldap_attr__7' => '[givenname]',
      '1__sm__convert__7' => FALSE,
      '1__sm__user_attr__7' => '[field.field_fname]',
      '1__sm__1__7' => TRUE,
      '1__sm__2__7' => TRUE,

      'ldapEntryProvisionTriggers[' . LdapUserConf::$provisionLdapEntryOnUserUpdateCreate . ']' => TRUE,
      'ldapEntryProvisionTriggers[' . LdapUserConf::$provisionLdapEntryOnUserAuthentication . ']' => TRUE,
      'ldapEntryProvisionTriggers[' . LdapUserConf::$provisionLdapEntryOnUserDelete . ']' => TRUE,

      '2__sm__user_attr__0' => 'user_tokens',
      '2__sm__user_tokens__0' => 'Drupal provisioned account for [property.uid]',
      '2__sm__convert__0' => FALSE,
      '2__sm__ldap_attr__0' => '[description]',
      '2__sm__4__3' => TRUE,
      '2__sm__4__3' => TRUE,

      '2__sm__user_attr__1' => '[property.uid]',
      '2__sm__user_tokens__1' => '',
      '2__sm__convert__1' => TRUE,
      '2__sm__ldap_attr__1' => '[guid]',
      '2__sm__4__1' => TRUE,
      '2__sm__4__1' => TRUE,

      '2__sm__user_attr__2' => 'user_tokens',
      '2__sm__user_tokens__2' => 'cn=[property.name]ou=people,dc=hogwarts,dc=edu',
      '2__sm__convert__2' => FALSE,
      '2__sm__ldap_attr__2' => '[dn]',
      '2__sm__4__2' => TRUE,
      '2__sm__4__2' => TRUE,
    );

    $this->drupalPost('admin/config/people/ldap/user', $edit, t('Save'));

    $ldap_user_conf = new LdapUserConf();
    foreach ($edit_direct_map as $property => $value) {
      $this->assertTrue($ldap_user_conf->{$property} == $value, $property . ' ' . t('field set correctly'), $this->testId('user interface tests'));
    }

    $this->assertTrue(
      isset($ldap_user_conf->drupalAcctProvisionTriggers[LdapUserConf::$provisionDrupalUserOnAuthentication]) &&
      isset($ldap_user_conf->drupalAcctProvisionTriggers[LdapUserConf::$provisionDrupalUserOnUserUpdateCreate]), t('drupal provision triggers set correctly'), $this->testId('user interface tests'));

    $this->assertTrue(
      isset($ldap_user_conf->ldapEntryProvisionTriggers[LdapUserConf::$provisionLdapEntryOnUserUpdateCreate]) &&
      isset($ldap_user_conf->ldapEntryProvisionTriggers[LdapUserConf::$provisionLdapEntryOnUserAuthentication]) &&
      isset($ldap_user_conf->ldapEntryProvisionTriggers[LdapUserConf::$provisionLdapEntryOnUserDelete]), t('ldap provision triggers  set correctly'), $this->testId('user interface tests'));

    $field_token = '[field.field_lname]';
    $field_lname_set_correctly = (
      $ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser][$field_token]['enabled'] == TRUE &&

      $ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser][$field_token]['ldap_attr'] == '[sn]');

    $this->assertTrue($field_lname_set_correctly, t('Sync mapping for field.field_lname  field set correctly'), $this->testId('user interface tests'));
    if (!$field_lname_set_correctly) {
      debug('ldap_user_conf->syncMapping[direction][field.field_lname]'); debug($ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser]['field.field_lname']);
    }

    $field_token = '[field.field_fname]';
    $field_fname_set_correctly = ($ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser][$field_token]['enabled'] == TRUE &&
      $ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser][$field_token]['direction'] == 1 &&
      $ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser][$field_token]['ldap_attr'] == '[givenname]');

    $this->assertTrue($field_fname_set_correctly, t('Sync mapping for field.field_lname  field set correctly'), $this->testId('user interface tests'));
    if (!$field_fname_set_correctly) {
      debug('ldap_user_conf->syncMapping[direction][field.field_lname]'); debug($ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToDrupalUser]['field.field_lname']);
    }

  }

}
