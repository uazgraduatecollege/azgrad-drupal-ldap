<?php

namespace Drupal\Tests\ldap_user\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;

/**
 * @group ldap
 */
class IntegrationTests extends KernelTestBase {

  /**
   *
   */
  protected function setUp() {
    parent::setUp();
  }

  /**
   *
   */
  public function testUserCreation() {

    $this->assertTrue(TRUE);
    return;
    // TODO.
    foreach (['activedirectory1', 'openldap1'] as $test_sid) {
      $sids = [$test_sid];
      // This will create the proper ldap_user configuration from ldap_test/ldap_user.conf.inc.
      $this->prepTestData('hogwarts', $sids, 'provisionToLdap_' . $test_sid);

      // 9.B. Create and approve new user, populating first and last name.
      $username = 'bhautdeser';
      if ($user = user_load_by_name($username)) {
        $user->uid->delete();
      }
      $user_edit = [
        'name' => $username,
        'mail' => $username . '@hogwarts.org',
        'pass' => user_password(),
        'status' => 1,
      ];
      $user_acct = User::create();
      $user_acct->is_new = TRUE;
      $user_acct->field_fname['und'][0]['value'] = 'Bercilak';
      $user_acct->field_lname['und'][0]['value'] = 'Hautdesert';

      $factory = \Drupal::service('ldap.servers');
      $servers = $factory->getAllServers();
      $desired_dn = "cn=bhautdeser,ou=people,dc=hogwarts,dc=edu";

      $pre_entry = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
      $drupal_account = user_save($user_acct, $user_edit);
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
    }
  }

  /**
   *
   */
  public function testChangeLastName() {
    $this->assertTrue(TRUE);
    return;
    // TODO.
    // Change lastname and first name (in drupal) and save user to test ldapSync event handler
    // confirm that appropriate attributes were changed in ldap entry.
    $ldap_entry_pre = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
    $user_acct_pre = user_load_by_name('bhautdeser');
    $edit = [];
    $edit['field_fname']['und'][0]['value'] = 'Bredbeddle';
    $edit['field_lname']['und'][0]['value'] = 'Hautdesert';
    $user_acct = user_save($user_acct, $edit);
    $user_acct_post = user_load_by_name('bhautdeser');

    $ldap_entry_post = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');

    $ldap_entry_success = (
      $ldap_entry_post['givenname'][0] == 'Bredbeddle'
      && $ldap_entry_post['displayname'][0] == 'Bredbeddle Hautdesert'
      && $ldap_entry_post['sn'][0] == 'Hautdesert'
    );
    $this->assertTrue($ldap_entry_success, t("sync to ldap entry on user save succeeded for " . $username), $this->testId());

  }

  /**
   *
   */
  public function testUserNameChange() {

    $this->assertTrue(TRUE);
    return;
    // TODO.
    // Change username and first name (in drupal) and save user to test ldapSync event handler
    // confirm that appropriate attributes were changed in ldap entry.
    $ldap_entry_pre = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
    $user_acct_pre = user_load_by_name('bhautdeser');
    $edit = [];
    $edit['field_fname']['und'][0]['value'] = 'Bredbeddle';
    $edit['field_lname']['und'][0]['value'] = 'Hautdesert';
    $user_acct = user_save($user_acct, $edit);
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
   *
   */
  public function testUserDeletion() {
    $this->assertTrue(TRUE);
    return;
    // TODO.
    // Test deletion of drupal entry on deletion of drupal user.
    foreach (['activedirectory1', 'openldap1'] as $test_sid) {
      $test_id = $test_sid;
      // 1. setup.
      $sids = [$test_sid];
      // This will create the proper ldap_user configuration from ldap_test/ldap_user.conf.inc.
      $this->prepTestData('hogwarts', $sids, 'provisionToLdap_' . $test_sid);

      if (!in_array(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE, $ldap_user_conf->ldapEntryProvisionTriggers)) {
        $ldap_user_conf->ldapEntryProvisionTriggers[] = LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE;
      }
      $ldap_user_conf->save();

      $username = 'bhautdeser';
      if ($user = user_load_by_name($username)) {
        $user->uid->delete();
      }
      $user_edit = [
        'name' => $username,
        'mail' => $username . '@hogwarts.org',
        'pass' => user_password(),
        'status' => 1,
      ];
      $user_acct = new stdClass();
      $user_acct->is_new = TRUE;
      $user_acct->field_fname['und'][0]['value'] = 'Bercilak';
      $user_acct->field_lname['und'][0]['value'] = 'Hautdesert';

      $desired_dn = "cn=bhautdeser,ou=people,dc=hogwarts,dc=edu";

      $pre_entry = $servers[$test_sid]->dnExists($desired_dn, 'ldap_entry');
      $drupal_account = user_save($user_acct, $user_edit);
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

    /**
     * @todo functional tests
     *        * do a password reset of some sort
     * try to add a drupal user that conflicts with an ldap user
     * try a binary fields such as a user profile image
     */
  }

}
