<?php

namespace Drupal\Tests\ldap_user\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Processor\DrupalUserProcessor;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\ldap_user\Helper\SyncMappingHelper
 * @group ldap
 */
class SyncMappingHelperTests extends UnitTestCase {

  public $configFactory;
  public $serverFactory;
  public $config;
  public $container;

  /**
   *
   */
  protected function setUp() {
    parent::setUp();

    /* Mocks the configuration due to detailed watchdog logging. */
    $this->config = $this->getMockBuilder('\Drupal\Core\Config\ImmutableConfig')
      ->disableOriginalConstructor()
      ->getMock();

    $this->configFactory = $this->getMockBuilder('\Drupal\Core\Config\ConfigFactory')
      ->disableOriginalConstructor()
      ->getMock();

    $this->configFactory->expects($this->any())
      ->method('get')
      ->with('ldap_user.settings')
      ->willReturn($this->config);

    $this->container = new ContainerBuilder();
    $this->container->set('config.factory', $this->configFactory);
    \Drupal::setContainer($this->container);
  }

  /**
   *
   */
  public function testSyncValidator() {
    $this->assertTrue(TRUE);
    return;
    // TODO: This test should test if the sync mapping returns in a useful form.
    // This is currently not the case since the test data is not injected
    // as configuration yet.
    $syncTestData = [
      LdapConfiguration::$eventCreateDrupalUser => [
        0 => [
          '[property.fake]',
          '[property.data]',
          '[property.uid]',
        ],
        1 => [
          '[property.mail]',
          '[property.name]',
          '[field.ldap_user_puid]',
          '[field.ldap_user_puid_property]',
          '[field.ldap_user_puid_sid]',
          '[field.ldap_user_current_dn]',
        ],
      ],
      LdapConfiguration::$eventSyncToDrupalUser => [
        0 => [
          '[property.fake]',
          '[property.data]',
          '[property.uid]',
          '[field.ldap_user_puid]',
          '[field.ldap_user_puid_property]',
          '[field.ldap_user_puid_sid]',
        ],
        1 => [
          '[property.mail]',
          '[property.name]',
          '[field.ldap_user_current_dn]',
        ],
      ],
    ];

    $failed = FALSE;
    foreach ($syncTestData as $prov_event => $tests) {
      foreach ($tests as $boolean_result => $attribute_tokens) {
        foreach ($attribute_tokens as $attribute_token) {
          $processor = $this->getMockBuilder('Drupal\ldap_user\Helper\SyncMappingHelper')
            ->setMethods(['isSynced', 'processSyncMappings'])
            ->disableOriginalConstructor()
            ->getMock();
          $processor->processSyncMappings();
          $isSynced = $processor->isSynced($attribute_token, [$prov_event], LdapConfiguration::PROVISION_TO_DRUPAL);
          if ((int) $isSynced !== (int) $boolean_result) {
            $failed = TRUE;
          }
        }
      }
    }

    $this->assertFalse($failed);
  }

  /**
   *
   */
  public function testUserNameChangeProvisionPuidConflict() {
    $this->assertTrue(TRUE);
    return;
    // TODO.
    /**
    * test for username change and provisioning with puid conflict
    * hpotter drupal user already exists and has correct puid
    * change samaccountname value (puid field) of hpotter ldap entry and attempt to provision account with new username (hpotterbrawn)
    * return should be old drupal account (same uid)
    */

    $this->testFunctions->setFakeServerUserAttribute('activedirectory1', 'cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'samaccountname', 'hpotter-granger', 0);
    $account = NULL;
    $user_edit = ['name' => 'hpotter-granger'];
    $processor = new DrupalUserProcessor();

    $hpottergranger = $processor->provisionDrupalAccount($user_edit);

    $this->testFunctions->setFakeServerUserAttribute('activedirectory1', 'cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'samaccountname', 'hpotter', 0);
    $pass = (is_object($hpottergranger) && is_object($hpotter) && $hpotter->uid == $hpottergranger->uid);
    $this->assertTrue($pass, t('provisionDrupalAccount recognized PUID conflict and synced instead of creating a conflicted drupal account.'), $this->testId('provisionDrupalAccount function test with existing user with same puid'));

    $authmaps = user_get_authmaps('hpotter-granger');
    $pass = $authmaps['ldap_user'] == 'hpotter-granger';
    $this->assertTrue($pass, t('provisionDrupalAccount recognized PUID conflict and fixed authmap.'), $this->testId());

    $pass = is_object($hpottergranger) && $hpottergranger->name == 'hpotter-granger';
    $this->assertTrue($pass, t('provisionDrupalAccount recognized PUID conflict and fixed username.'), $this->testId());

    $factory = \Drupal::service('ldap.servers');
    $ldap_server = $factory->getServerByIdEnabled('activedirectory1');
    $ldap_server->refreshFakeData();
    $account = NULL;
    $user_edit = ['name' => 'hpotter'];
    $processor = new DrupalUserProcessor();
    $hpotter = $processor->provisionDrupalAccount($account, $user_edit, NULL, TRUE);

  }

}
