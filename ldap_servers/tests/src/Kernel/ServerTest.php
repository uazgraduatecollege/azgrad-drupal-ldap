<?php

declare(strict_types=1);

namespace Drupal\Tests\ldap_servers\Kernel;

use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\ldap_servers\Entity\Server;
use Symfony\Component\Ldap\Entry;

/**
 * @coversDefaultClass \Drupal\ldap_servers\Entity\Server
 * @group ldap
 */
class ServerTest extends EntityKernelTestBase {

  /**
   * {@inheritdoc}
   */
  public static $modules = ['ldap_servers', 'externalauth'];

  /**
   * Server.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  protected $server;

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();
    $this->installEntitySchema('ldap_server');
    $this->server = Server::create(['id' => 'example']);
  }

  /**
   * Test derive user name.
   */
  public function testDeriveUserName(): void {
    $entry = new Entry('cn=hpotter,ou=people,dc=example,dc=org');
    $entry->setAttribute('samAccountName', ['hpotter']);
    $entry->setAttribute('username', ['harry']);

    // Default case, only user_attr set.
    $this->server->set('user_attr', 'samAccountName');
    $this->assertEquals('hpotter', $this->server->deriveUsernameFromLdapResponse($entry));
    $this->server->set('account_name_attr', 'username');
    $this->assertEquals('harry', $this->server->deriveUsernameFromLdapResponse($entry));
  }

  /**
   * Test the Base DN.
   */
  public function testGetBasedn(): void {
    $this->server->set('basedn', '');
    $this->assertEquals([], $this->server->getBaseDn());
    $this->server->set('basedn', "ou=people,dc=hogwarts,dc=edu\r\nou=groups,dc=hogwarts,dc=edu");
    $this->assertEquals('ou=groups,dc=hogwarts,dc=edu', $this->server->getBaseDn()[1]);
    $this->assertTrue(count($this->server->getBaseDn()) == 2);
  }

  /**
   * Test getting username from LDAP entry.
   */
  public function testDeriveAttributesFromLdapResponse(): void {

    $this->server->set('account_name_attr', '');
    $this->server->set('user_attr', 'cn');
    $this->server->set('mail_attr', 'mail');
    $this->server->set('unique_persistent_attr', 'guid');

    $empty_entry = new Entry('undefined', []);
    $this->assertEquals('', $this->server->deriveUsernameFromLdapResponse($empty_entry));
    $this->assertEquals('', $this->server->deriveEmailFromLdapResponse($empty_entry));

    $userOpenLdap = new Entry('cn=hpotter,ou=people,dc=hogwarts,dc=edu', [
      'cn' => [0 => 'hpotter'],
      'mail' => [
        0 => 'hpotter@hogwarts.edu',
        1 => 'hpotter@students.hogwarts.edu',
      ],
      'uid' => [0 => '1'],
      'guid' => [0 => '101'],
      'sn' => [0 => 'Potter'],
      'givenname' => [0 => 'Harry'],
      'house' => [0 => 'Gryffindor'],
      'department' => [0 => ''],
      'faculty' => [0 => 1],
      'staff' => [0 => 1],
      'student' => [0 => 1],
      'gpa' => [0 => '3.8'],
      'probation' => [0 => 1],
      'password' => [0 => 'goodpwd'],
    ]);

    $this->assertEquals('hpotter', $this->server->deriveUsernameFromLdapResponse($userOpenLdap));
    $this->assertEquals('hpotter@hogwarts.edu', $this->server->deriveEmailFromLdapResponse($userOpenLdap));

    $userOpenLdap->removeAttribute('mail');
    $this->server->set('mail_template', '[cn]@template.com');
    $this->assertEquals('hpotter@template.com', $this->server->deriveEmailFromLdapResponse($userOpenLdap));

    $this->assertEquals('101', $this->server->derivePuidFromLdapResponse($userOpenLdap));

    $this->server->set('unique_persistent_attr_binary', TRUE);
    $userOpenLdap->setAttribute('guid', ['Rr0by/+kSEKzVGoWnkpQ4Q==']);
    $this->assertEquals('52723062792f2b6b53454b7a56476f576e6b705134513d3d', $this->server->derivePuidFromLdapResponse($userOpenLdap));
  }

}
