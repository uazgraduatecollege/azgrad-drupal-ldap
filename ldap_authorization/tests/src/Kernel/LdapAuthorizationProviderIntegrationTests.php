<?php

namespace Drupal\Tests\authorization_drupal_user\Kernel;

use Drupal\authorization_drupal_roles\Plugin\authorization\Consumer\DrupalRolesConsumer;
use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;

/**
 * Integration tests for LdapAuthorizationProvider.
 *
 * @group ldap
 */
class LdapAuthorizationProviderIntegrationTests extends EntityKernelTestBase {

  /**
   * {@inheritdoc}
   */
  public static $modules = [
    'user',
    'system',
    'field',
    'text',
    'filter',
    'entity_test',
    'authorization',
    'ldap_servers',
    'ldap_authorization',
  ];

  /**
   * Consumer plugin.
   *
   * @var \Drupal\authorization_drupal_roles\Plugin\authorization\Consumer\DrupalRolesConsumer
   */
  protected $consumerPlugin;

  /**
   * Setup of kernel tests.
   */
  public function setUp() {
    parent::setUp();

    $this->installEntitySchema('user');
    $this->installConfig(['field', 'text']);

    $this->consumerPlugin = $this->getMockBuilder(DrupalRolesConsumer::class)
      ->disableOriginalConstructor()
      ->setMethods(NULL)
      ->getMock();

    // TODO: Write tests.
  }

}