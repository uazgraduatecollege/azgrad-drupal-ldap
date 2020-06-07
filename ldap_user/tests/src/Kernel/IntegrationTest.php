<?php

declare(strict_types = 1);

namespace Drupal\Tests\ldap_user\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\user\Entity\User;

/**
 * Integration tests for ldap_user.
 *
 * @group ldap
 */
class IntegrationTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  public static $modules = [
    'authorization',
    'externalauth',
    'ldap_servers',
    'ldap_user',
    'ldap_query',
    'user',
  ];

  /**
   * Config Factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * Setup of kernel tests.
   */
  public function setUp() {
    parent::setUp();
    $this->installConfig(['ldap_user']);
    $this->configFactory = $this->container->get('config.factory');
  }

  /**
   * Test module installation via configuration.
   */
  public function testConfig() {
    $value = $this->configFactory->get('ldap_user.settings')->get('orphanedAccountCheckInterval');
    $this->assertEquals('weekly', $value);
  }

  /**
   * Test the integration of the user processor.
   */
  public function brokenTestProcessor() {
    $processor = \Drupal::service('ldap.drupal_user_processor');
    $processor->createDrupalUserFromLdapEntry(['name' => 'hpotter']);
    $user = $processor->getUserAccount();
    // @TODO: Inject a server configuration for the provisioning server,
    // override the server factory to provide a dummy server.
    $this->assertInstanceOf(User::class, $user);
    // @TODO: Amend test scenario to user update, user insert, user delete.
    // @TODO: Amend test scenario to log user in, i.e. drupalUserLogsIn().
  }

}