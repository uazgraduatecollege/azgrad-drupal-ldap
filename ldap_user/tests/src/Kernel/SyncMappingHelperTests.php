<?php

namespace Drupal\Tests\ldap_user\Unit;

use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\ldap_servers\LdapUserAttributesInterface;

/**
 * @coversDefaultClass \Drupal\ldap_user\FieldProvider
 * @group ldap
 */
class FieldProviderTests extends EntityKernelTestBase implements LdapUserAttributesInterface {

  private $loggerChannel;
  private $moduleHandlerProphecy;
  private $configFactory;
  private $data;

  /**
   * Prepare the sync mapping tests.
   */
  protected function setUp() {
    parent::setUp();

    $this->data = [
      'drupal' => [
        'field.test_field' => [
          'ldap_attr' => '[cn]',
          'user_attr' => '[field.test_field]',
          'convert' => 'FALSE',
          'user_tokens' => '',
          'config_module' => 'ldap_user',
          'prov_module' => 'ldap_user',
          'prov_events' => [
            self::EVENT_CREATE_DRUPAL_USER,
          ],
        ],
        '[property.name]' => [
          'ldap_attr' => '[cn]',
          'user_attr' => '[field.test_field]',
          'convert' => TRUE,
          'user_tokens' => '',
          'config_module' => 'ldap_user',
          'prov_module' => 'ldap_user',
          'prov_events' => [
            self::EVENT_CREATE_DRUPAL_USER,
            self::EVENT_SYNC_TO_DRUPAL_USER,
          ],
        ],
      ],
      'ldap' => [
        'userPassword' => [
          'ldap_attr' => '[userPassword]',
          'user_attr' => '[password.user-only]',
          'convert' => FALSE,
          'user_tokens' => '',
          'config_module' => 'ldap_user',
          'prov_module' => 'ldap_user',
          'prov_events' => [
            self::EVENT_CREATE_LDAP_ENTRY,
            self::EVENT_SYNC_TO_LDAP_ENTRY,
          ],
        ],
        '[property.not_synced]' => [
          'ldap_attr' => '[userPassword]',
          'user_attr' => '',
          'convert' => FALSE,
          'user_tokens' => '',
          'config_module' => 'ldap_user',
          'prov_module' => 'ldap_user',
          'prov_events' => [
            self::EVENT_CREATE_LDAP_ENTRY,
            self::EVENT_SYNC_TO_LDAP_ENTRY,
          ],
        ],
      ],
    ];

    // TODO: load ldap_server as in the drupalprocessortest, add the server with mappings, test them.
    $this->loggerChannel = $this->prophesize(LoggerChannelInterface::class);
    $this->moduleHandlerProphecy = $this->prophesize(ModuleHandlerInterface::class);
    return;
    $this->configFactory = $this->getConfigFactoryStub([
      'ldap_user.settings' => ['ldapUserSyncMappings' => $this->data],
    ]);
  }

  /**
   * Prove that field syncs work and provide the demo data here.
   */
  public function testSyncValidatorIsSynced() {
    $this->markTestIncomplete('Needs to be rewritten now that SyncMappingHelper is gone.');
    $processor = new SyncMappingHelper(
      $this->loggerChannel->reveal(),
      $this->configFactory,
      $this->moduleHandlerProphecy->reveal()
    );

    /** @var \Drupal\ldap_user\Helper\SyncMappingHelper $processor */
    $isSynced = $processor->userDefinedSyncToDrupal('[field.test_field]', SyncMappingHelper::EVENT_CREATE_DRUPAL_USER);
    $this->assertTrue($isSynced);

    $isSynced = $processor->userDefinedSyncToLdap('[field.test_field]', SyncMappingHelper::EVENT_CREATE_LDAP_ENTRY);
    $this->assertFalse($isSynced);

    $isSynced = $processor->userDefinedSyncToLdap('[field.ldap_user_puid_sid]', SyncMappingHelper::EVENT_CREATE_LDAP_ENTRY);
    $this->assertFalse($isSynced);

    $isSynced = $processor->userDefinedSyncToLdap('[field.ldap_user_puid_sid]', SyncMappingHelper::EVENT_CREATE_LDAP_ENTRY);
    $this->assertFalse($isSynced);

    $isSynced = $processor->userDefinedSyncToLdap('[property.name]', SyncMappingHelper::EVENT_CREATE_LDAP_ENTRY);
    $this->assertTrue($isSynced);

    $isSynced = $processor->userDefinedSyncToDrupal('[property.xyz]', SyncMappingHelper::EVENT_CREATE_DRUPAL_USER);
    $this->assertFalse($isSynced);
  }

  /**
   * Prove that field syncs work and provide the demo data here.
   */
  public function testGetFieldsToLdap() {
    $this->markTestIncomplete('Needs to be rewritten now that SyncMappingHelper is gone.');

    $processor = new SyncMappingHelper(
      $this->loggerChannel->reveal(),
      $this->configFactory,
      $this->moduleHandlerProphecy->reveal()
    );

    $response = $processor->getUserDefinedFieldsSyncedToLdap(SyncMappingHelper::EVENT_CREATE_LDAP_ENTRY);
    $this->assertEquals($response, ['[property.name]']);
  }

}
