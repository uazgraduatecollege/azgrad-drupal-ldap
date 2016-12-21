<?php

namespace Drupal\ldap_user\Tests;

use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_servers\tests\LdapWebTestBase;
use Drupal\ldap_user\LdapUserConf;
use Drupal\ldap_user\SemaphoreStorage;
use Drupal\user\Entity\User;

/**
 * Integration tests for ldap_user.
 *
 * @group ldap_user
 */
class LdapWebUserIntegrationTests extends LdapWebTestBase {

  /**
   *
   */
  public static function getInfo() {
    return array(
      'name' => 'LDAP User Integration Tests',
      'description' => 'Test provisioning and syncing in real contexts such as account creation on logon, syncing on user edit, etc.',
      'group' => 'LDAP User',
    );
  }

  public static $modules = array('ldap_servers', 'ldap_authentication', 'ldap_authorization', 'ldap_user');

  public $module_name = 'ldap_user';
  protected $ldap_test_data;

  /**
   * Create one or more server configurations in such as way
   *  that this setUp can be a prerequisite for ldap_authentication and ldap_authorization.
   */

  /* @FIXME
   * This looks like another module's variable. You'll need to rewrite this call
   * to ensure that it uses the correct configuration object.
   * function setUp() {
   * parent::setUp();
   * variable_set('ldap_simpletest', 2);
  }
   */



  /*    @FIXME
  This looks like another module's variable. You'll need to rewrite this call
  to ensure that it uses the correct configuration object.
  function tearDown() {
  parent::tearDown();
  variable_del('ldap_help_watchdog_detail');
   */

  /*
  @FIXME
  This looks like another module's variable. You'll need to rewrite this call
  to ensure that it uses the correct configuration object.
  variable_del('ldap_simpletest');
  }
   */

  /**
   * Integration tests for provisioning to ldap.
   */
  public function testProvisionToLdap() {

    // Just to give warning if setup doesn't succeed.  may want to take these out at some point.
    /* @FIXME
     * This looks like another module's variable. You'll need to rewrite this call
     * to ensure that it uses the correct configuration object.
     * $setup_success = (
     *    module_exists('ldap_user') &&
     *    module_exists('ldap_servers') &&
     *    (variable_get('ldap_simpletest', 2) > 0)
     * );
     *
     * $this->assertTrue($setup_success, ' ldap_user setup successful', $this->testId("setup"));
     */

    foreach (array('activedirectory1', 'openldap1') as $test_sid) {
      $sids = array($test_sid);
      // This will create the proper ldap_user configuration from ldap_test/ldap_user.conf.inc.
      $this->prepTestData('hogwarts', $sids, 'provisionToLdap_' . $test_sid);
      $ldap_user_conf = new LdapUserConf();

      // 9.B. Create and approve new user, populating first and last name.
      $username = 'bhautdeser';
      if ($user = user_load_by_name($username)) {
        $user->uid->delete();
      }
      $user_edit = array(
        'name' => $username,
        'mail' => $username . '@hogwarts.org',
        'pass' => user_password(),
        'status' => 1,
      );
      // @FIXME: Not a user
      $user_acct = new User();
      $user_acct->is_new = TRUE;
      $user_acct->field_fname['und'][0]['value'] = 'Bercilak';
      $user_acct->field_lname['und'][0]['value'] = 'Hautdesert';

      $factory = \Drupal::service('ldap.servers');
      $servers = $factory->getAllServers();
      $desired_dn = "cn=bhautdeser,ou=people,dc=hogwarts,dc=edu";

      $pre_entry = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
      // @FIXME
      // user_save() is now a method of the user entity.
      // $drupal_account = user_save($user_acct, $user_edit);
      $ldap_entry_post = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

      $ldap_entry_success = (
        $ldap_entry_post &&
        $ldap_entry_post['cn'][0] == 'bhautdeser' &&
        $ldap_entry_post['displayname'][0] == 'Bercilak Hautdesert' &&
        $ldap_entry_post['sn'][0] == 'Hautdesert' &&
        $ldap_entry_post['guid'][0] == '151' &&
        $ldap_entry_post['provisionsource'][0] == 'drupal.hogwarts.edu'
      );
      $this->assertTrue($ldap_entry_success, t("provision of ldap entry on user create succeeded for " . $username), $this->testId("test for provision to ldap on drupal acct create"));
      if (!$ldap_entry_success) {
        // @FIXME: See above
        debug("desired_dn=$desired_dn, ldap_entry_post=");
        debug($ldap_entry_post);
        debug('ldap_user_conf'); debug($ldap_user_conf);
      }

      // Need to reset for simpletests.
      SemaphoreStorage::flushAllValues();

      // Change lastname and first name (in drupal) and save user to test ldapSync event handler
      // confirm that appropriate attributes were changed in ldap entry.
      $ldap_entry_pre = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
      $user_acct_pre = user_load_by_name('bhautdeser');
      $edit = array();
      $edit['field_fname']['und'][0]['value'] = 'Bredbeddle';
      $edit['field_lname']['und'][0]['value'] = 'Hautdesert';
      // @FIXME
      // user_save() is now a method of the user entity.
      // $user_acct = user_save($user_acct, $edit);
      $user_acct_post = user_load_by_name('bhautdeser');

      $ldap_entry_post = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

      $ldap_entry_success = (
        $ldap_entry_post['givenname'][0] == 'Bredbeddle'
        && $ldap_entry_post['displayname'][0] == 'Bredbeddle Hautdesert'
        && $ldap_entry_post['sn'][0] == 'Hautdesert'
      );

      $this->assertTrue($ldap_entry_success, t("sync to ldap entry on user save succeeded for " . $username), $this->testId());
      if (!$ldap_entry_success) {
        debug("dn=$desired_dn");
        debug('drupal_account pre'); debug($user_acct_pre);
        debug('drupal_account post'); debug($user_acct_post);
        debug('ldap_entry_pre'); debug($ldap_entry_pre);
        debug('ldap_entry_post'); debug($ldap_entry_post);
        debug('ldap_user_conf'); debug($ldap_user_conf);
      }

      // Change username and first name (in drupal) and save user to test ldapSync event handler
      // confirm that appropriate attributes were changed in ldap entry.
      $ldap_entry_pre = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
      $user_acct_pre = user_load_by_name('bhautdeser');
      $edit = array();
      $edit['field_fname']['und'][0]['value'] = 'Bredbeddle';
      $edit['field_lname']['und'][0]['value'] = 'Hautdesert';
      // @FIXME
      // user_save() is now a method of the user entity.
      // $user_acct = user_save($user_acct, $edit);
      $user_acct_post = user_load_by_name('bhautdeser');


      /* @var Server $servers[$test_sid] */
      $ldap_entry_post = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

      $ldap_entry_success = (
        $ldap_entry_post['givenname'][0] == 'Bredbeddle'
        && $ldap_entry_post['displayname'][0] == 'Bredbeddle Hautdesert'
        && $ldap_entry_post['sn'][0] == 'Hautdesert'
      );

      $this->assertTrue($ldap_entry_success, t("sync to ldap entry on user save succeeded for " . $username), $this->testId());
      if (!$ldap_entry_success) {
        debug("dn=$desired_dn");
        debug('drupal_account pre'); debug($user_acct_pre);
        debug('drupal_account post'); debug($user_acct_post);
        debug('ldap_entry_pre'); debug($ldap_entry_pre);
        debug('ldap_entry_post'); debug($ldap_entry_post);
        debug('ldap_user_conf'); debug($ldap_user_conf);
      }
    }

    /**
     * provisionToLdapEmailVerification
     * use case where a user self creates and confirms a drupal account and
     *  a corresponding ldap entry with password is created
     */
    $password_tests = array(
      '[password.user-random]' => 'goodpwd',
      '[password.random]' => 'random',
    );

    foreach ($password_tests as $password_token => $password_result) {
      $test_id = "provisionToLdapEmailVerification $password_token, $test_sid";
      // Need to reset for simpletests.
      SemaphoreStorage::flushAllValues();
      /**
       * provisionToLdapEmailVerification setup
       */
      // This will create the proper ldap_user configuration from ldap_test/ldap_user.conf.inc.
      $this->prepTestData('hogwarts', $sids, 'provisionToLdap_' . $test_sid);
      // Fixme: Test broken since LdapUserConfAdmin gone.
      $ldap_user_conf = new LdapUserConf();
      // Turn off provisioning to drupal.
      $config = \Drupal::service('config.factory')->getEditable('ldap_user.settings');
      $config->set('drupalAcctProvisionServer', 0)
        ->set('ldapEntryProvisionServer', $test_id)
        ->set('ldapEntryProvisionTriggers', [
          LdapUserConf::$provisionLdapEntryOnUserUpdateCreate,
          LdapUserConf::$provisionLdapEntryOnUserAuthentication,
        ])
        ->save();

      $ldap_user_conf->ldapUserSyncMappings[LdapUserConf::$provisioningDirectionToLDAPEntry]['[password]'] = array(
        'sid' => $test_sid,
        'ldap_attr' => '[password]',
        'user_attr' => 'user_tokens',
        'convert' => 0,
        'user_tokens' => $password_token,
        'config_module' => 'ldap_user',
        'sync_module' => 'ldap_user',
        'enabled' => 1,
        'prov_events' => array(LdapUserConf::$eventCreateLdapEntry, LdapUserConf::$eventSyncToLdapEntry),
      );

      $ldap_user_conf->save();
      $ldap_user_conf = new LdapUserConf();
      // @FIXME
      // // @FIXME
      // // This looks like another module's variable. You'll need to rewrite this call
      // // to ensure that it uses the correct configuration object.
      // variable_set('user_email_verification', TRUE);.
      // @FIXME
      // // @FIXME
      // // This looks like another module's variable. You'll need to rewrite this call
      // // to ensure that it uses the correct configuration object.
      // variable_set('user_register', USER_REGISTER_VISITORS);
      // or USER_REGISTER_ADMINISTRATORS_ONLY, USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL.
      // @FIXME
      // // @FIXME
      // // This looks like another module's variable. You'll need to rewrite this call
      // // to ensure that it uses the correct configuration object.
      // variable_set('user_cancel_method', 'user_cancel_block');
      // user_cancel_block_unpublish, user_cancel_reassign, user_cancel_delete.
      $username = 'sstephens';
      $this->drupalLogout();
      if ($sstephens = user_load_by_name($username)) {
        $sstephens->uid->delete();
      }

      /**
       * provisionToLdapEmailVerification test
       */
      // User register form.
      $this->drupalGet('user/register');
      $edit = array(
        'name' => $username,
        'mail' => $username . '@hogwarts.edu',
      );

      // This will create last and first name fields.
      $this->createTestUserFields();

      $this->drupalPost('user/register', $edit, t('Create new account'));

      $sstephens = user_load_by_name($username);

      // can't derive login url, must get it from outgoing email because timestamp in hash is not stored in user_mail_tokens()
      $emails = $this->drupalGetMails();
      // Most recent email is the one of interest.
      $email_body = $emails[count($emails) - 1]['body'];
      $result = array();
      preg_match_all('/(user\/reset\/.*)This link can only be/s', $email_body, $result, PREG_PATTERN_ORDER);
      if (count($result == 2)) {
        $login_path = trim($result[1][0]);
        // User login form.
        $this->drupalGet($login_path);
        $sstephens = user_load_by_name($username);
        $this->drupalPost($login_path, array(), t('Log in'));
        $sstephens = user_load_by_name($username);

        $edit = array(
          'mail' => $username . '@hogwarts.edu',
          'pass[pass1]' => 'goodpwd',
          'pass[pass2]' => 'goodpwd',
          'field_fname[und][0][value]' => 'Samantha',
          'field_lname[und][0][value]' => 'Stephens',
        );

        $this->drupalPost(NULL, $edit, t('Save'));
        $sstephens = user_load_by_name($username);

        $desired_dn = "cn=$username,ou=people,dc=hogwarts,dc=edu";
        $ldap_entry_post = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

        $password_success = (
          is_array($ldap_entry_post)
          &&
          (
            ($password_token == '[password.random]' && $ldap_entry_post['password'][0] && $ldap_entry_post['password'][0] != 'goodpwd')
            ||
            ($password_token == '[password.user-random]' && $ldap_entry_post['password'][0] == $password_result)
          )
        );
        $ldap_entry_success = (
          $password_success &&
          $ldap_entry_post['cn'][0] == $username &&
          $ldap_entry_post['displayname'][0] == 'Samantha Stephens' &&
          $ldap_entry_post['provisionsource'][0] == 'drupal.hogwarts.edu' &&
          $ldap_entry_post['sn'][0] == 'Stephens' &&
          $ldap_entry_post['givenname'][0] == 'Samantha'
        );
      }
      else {
        $ldap_entry_success = FALSE;
      }

      $this->assertTrue($ldap_entry_success, t("correct ldap entry created for " . $username), $this->testId($test_id));
      if (!$ldap_entry_success) {
        debug("password_success=$password_success,password_token,password_result: $password_token, $password_result");
        debug('ldap_user_conf'); debug($ldap_user_conf);
        debug('ldap_entry_post'); debug($ldap_entry_post);
        debug('user'); debug($sstephens);
      }
      /**
       * @todo functional tests
       *        * do a password reset of some sort
       * try to add a drupal user that conflicts with an ldap user
       * try a binary fields such as a user profile image
       */

    }

    // Test deletion of drupal entry on deletion of drupal user.
    foreach (array('activedirectory1', 'openldap1') as $test_sid) {
      $test_id = $test_sid;
      // 1. setup.
      $sids = array($test_sid);
      // This will create the proper ldap_user configuration from ldap_test/ldap_user.conf.inc.
      $this->prepTestData('hogwarts', $sids, 'provisionToLdap_' . $test_sid);
      // Fixme: Test broken since LdapUserConfAdmin gone.
      $ldap_user_conf = new LdapUserConf();
      if (!in_array(LdapUserConf::$provisionLdapEntryOnUserDelete, $ldap_user_conf->ldapEntryProvisionTriggers)) {
        $ldap_user_conf->ldapEntryProvisionTriggers[] = LdapUserConf::$provisionLdapEntryOnUserDelete;
      }
      $ldap_user_conf->provisionsLdapEntriesFromDrupalUsers = TRUE;
      $ldap_user_conf->save();

      $username = 'bhautdeser';
      if ($user = user_load_by_name($username)) {
        $user->uid->delete();
      }
      $user_edit = array(
        'name' => $username,
        'mail' => $username . '@hogwarts.org',
        'pass' => user_password(),
        'status' => 1,
      );
      $user_acct = new stdClass();
      $user_acct->is_new = TRUE;
      $user_acct->field_fname['und'][0]['value'] = 'Bercilak';
      $user_acct->field_lname['und'][0]['value'] = 'Hautdesert';


      $desired_dn = "cn=bhautdeser,ou=people,dc=hogwarts,dc=edu";

      $pre_entry = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
      // @FIXME
      // user_save() is now a method of the user entity.
      // $drupal_account = user_save($user_acct, $user_edit);
      $ldap_entry_pre_delete = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

      $ldap_entry = $ldap_user_conf->getProvisionRelatedLdapEntry($drupal_account);

      // 2. test.
      $drupal_account->uid->delete();
      $factory = \Drupal::service('ldap.servers');
      $ldap_server = $factory->getServerById($test_sid);
      $ldap_entry_post_delete = $ldap_server->dnExists($desired_dn, 'ldap_entry');

      $success = (!$ldap_entry_post_delete);
      $this->assertTrue($success, t("ldap entry removed for $username on drupal user delete with deletion enabled."), $this->testId($test_id));

      if (!$success) {
        debug(" desired_dn=$desired_dn test_sid=$test_sid, ldap entry post:"); debug($ldap_entry_post_delete);
      }

    }
  }

  /**
   * Test cron function for dealing with ldap associated users who no longer have
   * ldap entries
   *  - fix search in fake server to deal with general or queries.
   *
   *  Simpletest approach:
   *  - loop through all options for user_cancel
   *      ldap_user_orphan_email
   * user_cancel_block, user_cancel_block_unpublish,
   * user_cancel_reassign, user_cancel_delete
   *    - automatically generate 70 ldap users with cns hpotter1-hpotter300
   *    - create 75 corresponding drupal uses that are ldap identified
   *    - delete 10 of the ldap entries
   *    - run cron
   *    - test for drupal accounts being dealt with correctly and or email sent.
   */
  public function testDrupalAccountsOrphaned() {
    // Just to give warning if setup doesn't succeed.  may want to take these out at some point.
    /** @FIXME
    * This looks like another module's variable. You'll need to rewrite this call
    * to ensure that it uses the correct configuration object.
    * $setup_success = (
    *         module_exists('ldap_user') &&
    *         module_exists('ldap_servers') &&
    *         (variable_get('ldap_simpletest', 2) > 0)
    *       );
    *
    *    $this->assertTrue($setup_success, ' ldap_user setup successful',  $this->testId('orphaned entries tests'));
    */
    $sids = array('activedirectory1');
    $this->prepTestData('hogwarts', $sids, 'provisionToDrupal', 'default');

    // Fixme: Test broken since LdapUserConfAdmin gone.
    $ldap_user_conf = new LdapUserConf();
    $drupal_form = $ldap_user_conf->drupalForm();
    $account_options = $drupal_form['basic_to_drupal']['orphanedDrupalAcctBehavior']['#options'];
    $cn_to_account = array();
    $factory = \Drupal::service('ldap.servers');
    $ldap_server = $factory->getServerById('activedirectory1');

    foreach ($account_options as $account_option => $account_option_text) {
      $sids = array('activedirectory1');
      $this->prepTestData('hogwarts', $sids, 'provisionToDrupal', 'default');
      // FIXME: Configuration no longer saved in LdapUserConfiguration.
      //$ldap_user_conf->orphanedDrupalAcctBehavior = $account_option;
      //$ldap_user_conf->save();
      $test_id = "ldap_user.orphans.$account_option";
      $test_text = "Test of orphaned Drupal account option: $account_option_text";
      $success = FALSE;

      // Create 70 drupal accounts (clone0 to clone69) based on corresponding ldap entries.
      $first_clone_username = 'clone0';
      $last_clone_username = 'clone' . (self::$userOrphanCloneCount - 1);
      // 70.
      for ($i = 0; $i < self::$userOrphanCloneCount; $i++) {
        $name = "clone" . $i;

        $account = $this->createLdapIdentifiedDrupalAccount(
          $ldap_user_conf,
          $name,
          'activedirectory1'
        );
        $cn_to_account[$name] = $account;
      }

      // Delete 10 ldap entries.
      $clone_first_uid = $cn_to_account[$first_clone_username]->uid;
      $clone_last_uid = $cn_to_account[$last_clone_username]->uid;
      // @FIXME
      $clone_first =
      // To reset the user cache, use EntityStorageInterface::resetCache().
      \Drupal::entityManager()->getStorage('user')->load($clone_first_uid);
      // @FIXME
      $clone_last =
      // To reset the user cache, use EntityStorageInterface::resetCache().
      \Drupal::entityManager()->getStorage('user')->load($clone_last_uid);

      $delete = self::$userOrphanCloneCount - self::$userOrphanCloneRemoveCount;
      for ($i = 0; $i < $delete; $i++) {
        $name = "clone" . $i;
        $account = $cn_to_account[$name];
        //  ?? is it possible the ldap delete hook is causing the drupal user to get populated with empty values?
        $ldap_server->delete($account->ldap_user_current_dn['und'][0]['value']);
      }

      // @FIXME
      $clone_first =
      // To reset the user cache, use EntityStorageInterface::resetCache().
      \Drupal::entityManager()->getStorage('user')->load($clone_first_uid);
      // @FIXME
      $clone_last =
      // To reset the user cache, use EntityStorageInterface::resetCache().
      \Drupal::entityManager()->getStorage('user')->load($clone_last_uid);
      \Drupal::service("cron")->run();
      // @FIXME
      $clone_first =
      // To reset the user cache, use EntityStorageInterface::resetCache().
      \Drupal::entityManager()->getStorage('user')->load($clone_first_uid);
      // @FIXME
      $clone_last =
      // To reset the user cache, use EntityStorageInterface::resetCache().
      \Drupal::entityManager()->getStorage('user')->load($clone_last_uid);
      switch ($account_option) {

        case 'ldap_user_orphan_do_not_check':
          $test_uids = array();
          // 70.
          for ($i = 0; $i < self::$userOrphanCloneCount; $i++) {
            $name = "clone" . $i;
            $test_uids[] = @$cn_to_account[$name]->uid;
          }
          $success = TRUE;
          $accounts = \Drupal::entityManager()->getStorage('user')->loadMultiple($test_uids);
          foreach ($accounts as $uid => $account) {
            if ($account->status != 1) {
              $success = FALSE;
              break;
            }
          }
          if ($success) {
            $success = ($clone_last && $clone_last->status == 1);
          }

          break;

        case 'ldap_user_orphan_email':
          // test is if email has 10 users and was sent.
          $emails = $this->drupalGetMails();
          if (count($emails)) {
            // Most recent email is the one of interest.
            $email_body = $emails[count($emails) - 1]['body'];
            $success = (strpos($email_body, "The following $delete Drupal users") !== FALSE);
          }
          else {
            $success = FALSE;
          }

          break;

        case 'user_cancel_block':
        case 'user_cancel_block_unpublish':
          // test is if clone0-clone9 have a status of 0
          // and clone12,11... have a status of 1.
          $test_uids = array();
          // 70.
          for ($i = 0; $i < $delete; $i++) {
            $name = "clone" . $i;
            $test_uids[] = @$cn_to_account[$name]->uid;
          }
          $success = TRUE;
          $accounts = \Drupal::entityManager()->getStorage('user')->loadMultiple($test_uids);
          foreach ($accounts as $uid => $account) {
            if ($account->status != 0) {
              $success = FALSE;
              break;
            }
          }
          if ($success) {
            // @FIXME
            $clone_last =
            // To reset the user cache, use EntityStorageInterface::resetCache().
            \Drupal::entityManager()->getStorage('user')->load($clone_last_uid);
            $success = ($clone_last && $clone_last->status == 1);
          }
          break;

        case 'user_cancel_reassign':
        case 'user_cancel_delete':
          // Test is if clone0-clone9 are deleted
          // and clone12,11... have a status of 1.
          $test_uids = array();
          // 70.
          for ($i = 0; $i < $delete; $i++) {
            $name = "clone" . $i;
            $test_uids[] = @$cn_to_account[$name]->uid;
          }
          $success = TRUE;
          $accounts = \Drupal::entityManager()->getStorage('user')->loadMultiple($test_uids);
          $success = (count($accounts) == self::$userOrphanCloneCount);

          if ($success) {
            // @FIXME
            $clone_last =
            // To reset the user cache, use EntityStorageInterface::resetCache().
            \Drupal::entityManager()->getStorage('user')->load($clone_last_uid);
            $success = ($clone_last && $clone_last->status == 1);
          }
          break;
      }

      $this->assertTrue($success, $test_id, $test_text);

      // Remove all drupal users except 1 for next test.
      foreach ($cn_to_account as $cn => $account) {
        @$account->uid->delete();
      }

    }

  }

  /**
   *
   */
  public function createLdapIdentifiedDrupalAccount($ldap_user_conf, $name, $sid) {

    $account = NULL;
    $user_edit = array('name' => $name);
    // @FIXME Missing function
    $user = $ldap_user_conf->provisionDrupalAccount($account, $user_edit, NULL, TRUE);

    // @FIXME
    // To reset the user cache, use EntityStorageInterface::resetCache().
    return \Drupal::entityManager()->getStorage('user')->load($user->uid);
  }

}
