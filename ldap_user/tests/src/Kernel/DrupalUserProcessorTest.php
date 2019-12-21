<?php

declare(strict_types=1);

namespace Drupal\Tests\ldap_user\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\user\Entity\User;

/**
 * Tests for the DrupalUserProcessor.
 *
 * @coversDefaultClass \Drupal\ldap_user\Processor\DrupalUserProcessor
 * @group ldap
 */
class DrupalUserProcessorTest extends KernelTestBase implements LdapUserAttributesInterface {

  /**
   * {@inheritdoc}
   */
  public static $modules = [
    'externalauth',
    'ldap_servers',
    'ldap_user',
    'ldap_query',
    'ldap_authentication',
    'user',
    'system',
  ];

  /**
   * Drupal User Processor.
   *
   * @var \Drupal\ldap_user\Processor\DrupalUserProcessor
   */
  private $drupalUserProcessor;

  /**
   * Entity Type Manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManager
   */
  private $entityTypeManager;

  /**
   * Provisioning events.
   *
   * @var array
   */
  private $provisioningEvents = [
    self::PROVISION_TO_DRUPAL => [
      self::EVENT_SYNC_TO_DRUPAL_USER,
      self::EVENT_SYNC_TO_DRUPAL_USER,
    ],

    self::PROVISION_TO_LDAP => [
      self::EVENT_SYNC_TO_LDAP_ENTRY,
      self::EVENT_CREATE_LDAP_ENTRY,
    ],
  ];

  /**
   * Setup of kernel tests.
   */
  public function setUp() {
    parent::setUp();

    $this->installConfig(['ldap_authentication']);
    $this->installConfig(['ldap_user']);
    $this->installConfig(['user']);
    $this->drupalUserProcessor = $this->container->get('ldap.drupal_user_processor');
    $this->entityTypeManager = $this->container->get('entity_type.manager');
  }

  /**
   * Tests user exclusion for the authentication helper.
   */
  public function testUserExclusion() {

    // Skip administrators, if so configured.
    $account = $this->prophesize('\Drupal\user\Entity\User');
    $account->getRoles()->willReturn(['administrator']);
    $account->id()->willReturn(1);
    $value = new \stdClass();
    $value->value = '';
    $account->get('ldap_user_ldap_exclude')->willReturn($value);
    $this->entityTypeManager
      ->getStorage('user_role')
      ->create([
        'id' => 'administrator',
        'label' => 'Administrators',
        'is_admin' => TRUE,
      ])
      ->save();
    $admin_roles = $this->entityTypeManager
      ->getStorage('user_role')
      ->getQuery()
      ->condition('is_admin', TRUE)
      ->execute();
    $this->assertNotEmpty($admin_roles);
    $this->assertTrue($this->drupalUserProcessor->excludeUser($account->reveal()));
    $this->config('ldap_authentication.settings')->set('skipAdministrators', 0)->save();
    $this->assertFalse($this->drupalUserProcessor->excludeUser($account->reveal()));

    // Disallow checkbox exclusion (everyone else allowed).
    $account = $this->prophesize(User::class);
    $account->getRoles()->willReturn(['']);
    $account->id()->willReturn(2);
    $value = new \stdClass();
    $value->value = 1;
    $account->get('ldap_user_ldap_exclude')->willReturn($value);
    $this->assertTrue($this->drupalUserProcessor->excludeUser($account->reveal()));

    // Everyone else allowed.
    $account = $this->prophesize(User::class);
    $account->getRoles()->willReturn(['']);
    $account->id()->willReturn(2);
    $value = new \stdClass();
    $value->value = '';
    $account->get('ldap_user_ldap_exclude')->willReturn($value);
    $this->assertFalse($this->drupalUserProcessor->excludeUser($account->reveal()));
  }

  /**
   * Test that creating users with createDrupalUserFromLdapEntry() works.
   */
  public function testProvisioning() {
    $this->markTestIncomplete('Broken test');
    $result = $this->drupalUserProcessor->createDrupalUserFromLdapEntry(['name' => 'hpotter']);
    $this->assertTrue($result);
    $user = $this->drupalUserProcessor->getUserAccount();
    // Override the server factory to provide a dummy server.
    $this->assertInstanceOf(User::class, $user);
    // @TODO: Does not work since getUserDataFromServerByIdentifier() loads
    // live data and the server is missing.
    // @TODO: Amend test scenario to user update, user insert, user delete.
    // @TODO: Amend test scenario to log user in, i.e. drupalUserLogsIn().
  }

  // @TODO: Write test to show that syncing to existing Drupal users works.
  // @TODO: Write a test showing that a constant value gets passend on
  // correctly, i.e. ldap_attr is "Faculty" instead of [type].
  // @TODO: Write a test validating compound tokens, i.e. ldap_attr is
  // '[cn]@hogwarts.edu' or '[givenName] [sn]'.
  // @TODO: Write a test validating multiple mail properties, i.e. [mail]
  // returns the following and we get both:
  // [['mail' => 'hpotter@hogwarts.edu'], ['mail' => 'hpotter@owlmail.com']].
  // @TODO: Write a test validating non-integer values on the account status.
  // @TODO: Write a test for applyAttributes for binary fields.
  // @TODO: Write a test for applyAttributes for case sensitivity in tokens.
  // @TODO: Write a test for applyAttributes for user_attr in mappings.
  // @TODO: Write a test to prove puid update works, with and without binary mode
  // and including a conflicting account.
}
