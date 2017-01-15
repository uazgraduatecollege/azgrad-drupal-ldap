<?php

namespace Drupal\ldap_user\Tests;

use Drupal\ldap_servers\tests\LdapWebTestBase;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;
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
      $user_acct = User::create();
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

      /** @var Server $servers[$test_sid] */
      $ldap_entry_post = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

      $ldap_entry_success = (
        $ldap_entry_post['givenname'][0] == 'Bredbeddle'
        && $ldap_entry_post['displayname'][0] == 'Bredbeddle Hautdesert'
        && $ldap_entry_post['sn'][0] == 'Hautdesert'
      );

      $this->assertTrue($ldap_entry_success, t("sync to ldap entry on user save succeeded for " . $username), $this->testId());

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
      // Turn off provisioning to drupal.
      $config = \Drupal::service('config.factory')->getEditable('ldap_user.settings');
      $config->set('drupalAcctProvisionServer', 0)
        ->set('ldapEntryProvisionServer', $test_id)
        ->set('ldapEntryProvisionTriggers', [
          LdapConfiguration::$provisionLdapEntryOnUserUpdateCreate,
          LdapConfiguration::$provisionLdapEntryOnUserAuthentication,
        ])
        ->save();

      $ldap_user_conf->ldapUserSyncMappings[LdapConfiguration::$provisioningDirectionToLDAPEntry]['[password]'] = array(
        'sid' => $test_sid,
        'ldap_attr' => '[password]',
        'user_attr' => 'user_tokens',
        'convert' => 0,
        'user_tokens' => $password_token,
        'config_module' => 'ldap_user',
        'sync_module' => 'ldap_user',
        'enabled' => 1,
        'prov_events' => array(LdapConfiguration::$eventCreateLdapEntry, LdapConfiguration::$eventSyncToLdapEntry),
      );

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

      if (!in_array(LdapConfiguration::$provisionLdapEntryOnUserDelete, $ldap_user_conf->ldapEntryProvisionTriggers)) {
        $ldap_user_conf->ldapEntryProvisionTriggers[] = LdapConfiguration::$provisionLdapEntryOnUserDelete;
      }
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

      $ldap_entry = $ldap_user_conf->getProvisionRelatedLdapEntry($user_acct);

      // 2. test.
      $user_acct->uid->delete();
      $factory = \Drupal::service('ldap.servers');
      $ldap_server = $factory->getServerById($test_sid);
      $ldap_entry_post_delete = $ldap_server->dnExists($desired_dn, 'ldap_entry');

      $success = (!$ldap_entry_post_delete);
      $this->assertTrue($success, t("ldap entry removed for $username on drupal user delete with deletion enabled."), $this->testId($test_id));

    }
  }

}
