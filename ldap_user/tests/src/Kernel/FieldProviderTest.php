<?php

namespace Drupal\Tests\ldap_user\Kernel;

use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_user\FieldProvider;

/**
 * @coversDefaultClass \Drupal\ldap_user\FieldProvider
 * @group ldap
 */
class FieldProviderTest extends EntityKernelTestBase implements LdapUserAttributesInterface {

  /**
   * {@inheritdoc}
   */
  public static $modules = [
    'ldap_servers',
    'ldap_user',
    'ldap_query',
    'externalauth',
  ];

  /**
   * Server.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  protected $server;

  /**
   * Config input data.
   *
   * @var array
   */
  private $data;

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();
    $this->installEntitySchema('ldap_server');
    $this->installConfig('ldap_user');
    $this->server = Server::create([
      'id' => 'example',
      'picture_attr' => 'picture_field',
      'mail_attr' => 'mail',
      'unique_persistent_attr' => 'guid',
      'drupalAcctProvisionServer' => 'example',
    ]);

    $this->data = [
      'drupal' => [
        'field-test_field' => [
          'ldap_attr' => '[cn]',
          'user_attr' => '[field.test_field]',
          'convert' => FALSE,
          'user_tokens' => '',
          'config_module' => 'ldap_user',
          'prov_module' => 'ldap_user',
          'prov_events' => [
            self::EVENT_CREATE_DRUPAL_USER,
          ],
        ],
        'property-name' => [
          'ldap_attr' => '[cn]',
          'user_attr' => '[property.name]',
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
        'property-not_synced' => [
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
  }

  /**
   * Prove that field syncs work and provide the demo data here.
   */
  public function testSyncValidatorIsSynced() {
    $container = \Drupal::getContainer();
    $config_factory = $container->get('config.factory');
    $config = $config_factory->getEditable('ldap_user.settings');
    $config
      ->set('ldapUserSyncMappings', $this->data)
      ->set('drupalAcctProvisionTriggers', [
        'drupal_on_login' => 'drupal_on_login',
        'drupal_on_update_create' => 'drupal_on_update_create',
      ])
      ->save();
    $processor = new FieldProvider(
      $config_factory,
      $container->get('entity_type.manager'),
      $container->get('module_handler'),
      $container->get('entity_field.manager')
    );

    $processor->loadAttributes(FieldProvider::PROVISION_TO_DRUPAL, $this->server);
    $data = $processor->getConfigurableAttributesSyncedOnEvent(FieldProvider::EVENT_CREATE_DRUPAL_USER);
    $this->assertEquals(2, count($data));
    $this->assertEquals(2, count($data['[property.name]']->getProvisioningEvents()));
    $data = $processor->getConfigurableAttributesSyncedOnEvent(FieldProvider::EVENT_SYNC_TO_LDAP_ENTRY);
    $this->assertEmpty($data);

    $data = $processor->getAttributesSyncedOnEvent(FieldProvider::EVENT_CREATE_DRUPAL_USER);
    $this->assertEquals('not configurable', $data['[field.ldap_user_current_dn]']->getNotes());
    $this->assertTrue($data['[property.picture]']->isEnabled());
    $this->assertEquals('ldap_user', $data['[property.picture]']->getProvisioningModule());
    $this->assertEquals('[picture_field]', $data['[property.picture]']->getLdapAttribute());
    $this->assertEquals('[mail]', $data['[property.mail]']->getLdapAttribute());

    $this->assertTrue($processor->attributeIsSyncedOnEvent(
      '[property.name]',
      FieldProvider::EVENT_SYNC_TO_DRUPAL_USER));
    $this->assertFalse($processor->attributeIsSyncedOnEvent(
      '[field.test_field]',
      FieldProvider::EVENT_SYNC_TO_DRUPAL_USER));

    $this->assertEquals('[guid]', $data['[field.ldap_user_puid]']->getLdapAttribute());

    $this->server->set('mail_template', '[cn]@example.com');
    $processor->loadAttributes(FieldProvider::PROVISION_TO_DRUPAL, $this->server);
    $data = $processor->getAttributesSyncedOnEvent(FieldProvider::EVENT_SYNC_TO_DRUPAL_USER);
    $this->assertEquals('[cn]@example.com', $data['[property.mail]']->getLdapAttribute());
  }

}
