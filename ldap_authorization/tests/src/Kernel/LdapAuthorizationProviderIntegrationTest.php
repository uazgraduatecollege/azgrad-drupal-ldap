<?php

declare(strict_types = 1);

namespace Drupal\Tests\ldap_authorization\Kernel;

use Drupal\authorization\Entity\AuthorizationProfile;
use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers_dummy\FakeBridge;
use Drupal\ldap_servers_dummy\FakeCollection;
use Drupal\user\Entity\User;
use Symfony\Component\Ldap\Entry;

/**
 * Integration tests for LdapAuthorizationProvider.
 *
 * @group ldap
 */
class LdapAuthorizationProviderIntegrationTest extends EntityKernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'authorization',
    'externalauth',
    'ldap_authorization',
    'ldap_query',
    'ldap_servers',
    'ldap_servers_dummy',
    'ldap_user',
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
  public function setUp(): void {
    parent::setUp();

    $this->installConfig(['ldap_user']);
    $this->installEntitySchema('ldap_server');
    $this->installSchema('externalauth', 'authmap');

    $server = Server::create([
      'id' => 'example',
      'basedn' => ['ou=people,dc=hogwarts,dc=edu'],
      'user_attr' => 'cn',
      'mail_attr' => 'mail',
      'picture_attr' => 'picture_field',
      'grp_user_memb_attr_exists' => TRUE,
      'grp_user_memb_attr' => 'businessCategory',
      'grp_unused' => FALSE,
    ]);
    $server->save();

    $bridge = new FakeBridge(
      $this->container->get('logger.channel.ldap_servers'),
      $this->container->get('entity_type.manager')
    );
    $bridge->setServer($server);
    $collection = [
      '(cn=hpotter)' => new FakeCollection([
        new Entry(
          'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
          [
            'cn' => ['hpotter'],
            'uid' => ['123'],
            'mail' => ['hpotter@example.com'],
            'businessCategory' => [
              'student',
              'wizard',
            ],
          ],
        ),
      ]),
    ];
    $bridge->get()->setQueryResult($collection);
    $bridge->setBindResult(TRUE);
    $this->container->set('ldap.bridge', $bridge);
  }

  /**
   * Test Provider.
   */
  public function testProvider(): void {
    $profile = AuthorizationProfile::create([
      'status' => 'true',
      'description' => 'test',
      'id' => 'test',
      'provider' => 'ldap_provider',
      'consumer' => 'authorization_drupal_roles',
    ]);
    $profile->setProviderConfig([
      'status' => [
        'server' => 'example',
        'only_ldap_authenticated' => 1,
      ],
      'filter_and_mappings' => [
        'use_first_attr_as_groupid' => 0,
      ],
    ]);
    $profile->setProviderMappings([
      'is_regex' => 1,
      'query' => 'example',
    ]);
    $profile->setConsumerMappings([['role' => 'student']]);
    $provider = $profile->getProvider();

    $user = User::create(['name' => 'hpotter', 'mail' => 'hpotter@hogwarts.edu']);
    $user->save();

    $proposals = $provider->getProposals($user);
    self::assertEquals(['student' => 'student', 'wizard' => 'wizard'], $proposals);

    $sanitized = $provider->sanitizeProposals($proposals);
    self::assertEquals(['student' => 'student', 'wizard' => 'wizard'], $sanitized);
  }

  /**
   * Test Provider with simplified mapping on user.
   *
   * This test case is only correctly triggered with the actual LDAP extension
   * installed, i.e. removing the strpos() check in sanitizeProposals() will
   * not make this test fail without the extension.
   */
  public function testProviderMisconfiguration(): void {
    $profile = AuthorizationProfile::create([
      'status' => 'true',
      'description' => 'test',
      'id' => 'test',
      'provider' => 'ldap_provider',
      'consumer' => 'authorization_drupal_roles',
    ]);
    $profile->setProviderConfig([
      'status' => [
        'server' => 'example',
        'only_ldap_authenticated' => 1,
      ],
      'filter_and_mappings' => [
        'use_first_attr_as_groupid' => 1,
      ],
    ]);
    $profile->setProviderMappings([
      'is_regex' => 1,
      'query' => 'example',
    ]);
    $profile->setConsumerMappings([['role' => 'student']]);
    $provider = $profile->getProvider();

    $user = User::create(['name' => 'hpotter', 'mail' => 'hpotter@hogwarts.edu']);
    $user->save();

    self::assertEquals([
      'student' => 'student',
      'wizard' => 'wizard',
    ], $provider->sanitizeProposals($provider->getProposals($user)));
  }

}
