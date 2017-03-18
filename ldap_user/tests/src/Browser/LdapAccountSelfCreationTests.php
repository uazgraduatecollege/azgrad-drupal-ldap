<?php

namespace Drupal\Tests\ldap_user\Browser;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\KernelTests\KernelTestBase;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\UnitTestCase;

/**
 * @group ldap
 */
class LdapAccountSelfCreationTests extends BrowserTestBase {


  protected function setUp() {
    parent::setUp();
  }

  public function testUserCreation() {
    $this->assertTrue(true);
    return;
    // TODO

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

    }
  }

}
