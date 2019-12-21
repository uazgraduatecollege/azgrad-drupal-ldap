<?php

namespace Drupal\Tests\ldap_servers\Kernel;

use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\LdapUserManager;
use Symfony\Component\Ldap\Entry;

/**
 * @coversDefaultClass \Drupal\ldap_servers\Entity\Server
 * @group ldap
 */
class UnportedTest extends EntityKernelTestBase {

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
    $this->server = Server::create(['id' => 'example'])
      ->save();
  }

  /**
   * Tests searches across multiple DNs.
   *
   * TODO: Move to separate test class.
   */
  public function testSearchAllBaseDns(): void {
    $this->markTestIncomplete('Cannot be easily tested as is, research and implement mocking symfony/ldap responses.');

    $stub = $this->getMockBuilder()
      ->disableOriginalConstructor()
      ->setMethods(['search', 'getBasedn', 'bind'])
      ->getMock();

    $baseDn = 'ou=people,dc=example,dc=org';

    $validResult = [
      0 => ['dn' => ['cn=hpotter,ou=people,dc=example,dc=org']],
    ];
    $valueMap = [
      [$baseDn, '(|(cn=hpotter))', ['dn'], 0, 0, 0, NULL, 'sub'],
      [$baseDn, '(cn=hpotter)', ['dn'], 0, 0, 0, NULL, 'sub'],
      [$baseDn, 'cn=hpotter', ['dn'], 0, 0, 0, NULL, 'sub'],
    ];

    $stub->method('getBasedn')
      ->willReturn([$baseDn]);
    $stub->method('bind')
      ->willReturn(TRUE);

    $ldapStub = $this->getMockBuilder(LdapUserManager::class)
      ->setMethods(['query'])
      ->method('query')
      ->willReturnCallback(function () use ($valueMap, $validResult) {
        $arguments = func_get_args();

        foreach ($valueMap as $map) {
          if (!is_array($map) || count($arguments) !== count($map)) {
            continue;
          }

          if ($arguments === $map) {
            // TODO: This result needs to be a Collection.
            return $validResult;
          }
        }
        return ['count' => 0];
      });
    /** @var \Drupal\ldap_servers\LdapUserManager $ldapStub */
    $result = $ldapStub->searchAllBaseDns('(|(cn=hpotter,ou=people,dc=example,dc=org))', ['dn']);
    $this->assertEquals(1, $result['count']);
    $result = $ldapStub->searchAllBaseDns('(|(cn=invalid_cn,ou=people,dc=example,dc=org))', ['dn']);
    $this->assertEquals(0, $result['count']);
    $result = $ldapStub->searchAllBaseDns('(|(cn=hpotter))', ['dn']);
    $this->assertEquals(1, $result['count']);
    $result = $ldapStub->searchAllBaseDns('(cn=hpotter)', ['dn']);
    $this->assertEquals(1, $result['count']);
  }

  /**
   * Test getting the user name from AD via account_name_attr.
   */
  public function testUserUsernameActiveDirectory(): void {
    $stub = $this->getMockBuilder(Server::class)
      ->disableOriginalConstructor()
      ->setMethods(['getAccountNameAttribute', 'getAuthenticationNameAttribute'])
      ->getMock();

    // TODO: this does not cover the case sAMAccountName, verify if that's
    // normalized at an earlier place.
    $stub
      ->method('getAccountNameAttribute')
      ->willReturn('');
    $stub
      ->method('getAuthenticationNameAttribute')
      ->willReturn('samaccountname');

    /** @var \Drupal\ldap_servers\Entity\Server $stub */
    $username = $stub->deriveUsernameFromLdapResponse(new Entry('undefined', []));
    $this->assertEquals(FALSE, $username);

    $userActiveDirectory = new Entry('undefined', [
      'cn' => [0 => 'hpotter'],
      'mail' => [0 => 'hpotter@hogwarts.edu'],
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
      // Divergent data for AD below.
      'samaccountname' => [0 => 'hpotter'],
      'distinguishedname' => [
        0 => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
      ],
      'memberof' => [
        0 => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
        1 => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
        2 => 'cn=honors students,ou=groups,dc=hogwarts,dc=edu',
      ],
    ]);

    $username = $stub->deriveUsernameFromLdapResponse($userActiveDirectory);
    $this->assertEquals('hpotter', $username);

  }

  /**
   * Test the group membership of the user from an entry.
   */
  public function testGroupUserMembershipsFromEntry(): void {
    $this->markTestIncomplete('TODO: Unported');

    $user_dn = 'cn=hpotter,ou=people,dc=hogwarts,dc=edu';
    $user_ldap_entry = [
      'cn' => [0 => 'hpotter'],
      'mail' => [0 => 'hpotter@hogwarts.edu'],
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
      // Divergent data for AD below.
      'samaccountname' => [0 => 'hpotter'],
      'distinguishedname' => [
        0 => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
      ],
      'memberof' => [
        0 => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
        1 => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
        2 => 'cn=honors students,ou=groups,dc=hogwarts,dc=edu',
      ],
    ];

    $desired = [];
    $desired[0] = [
      0 => 'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
      1 => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
      2 => 'cn=honors students,ou=groups,dc=hogwarts,dc=edu',
    ];
    $desired[1] = array_merge($desired[0], ['cn=users,ou=groups,dc=hogwarts,dc=edu']);

    foreach ([0, 1] as $nested) {

      // TODO: Before porting this test, consider splitting nested and
      // not-nested functions up, since this is a mess.
      $nested_display = ($nested) ? 'nested' : 'not nested';
      $desired_count = ($nested) ? 4 : 3;
      $ldap_module_user_entry = ['attr' => $user_ldap_entry, 'dn' => $user_dn];
      $groups_desired = $desired[$nested];

      /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
      // Test parent function groupMembershipsFromUser.
      // TODO: Comment out / remove placeholder.
      // $groups = $ldap_server->
      // groupMembershipsFromUser($ldap_module_user_entry, $nested);.
      $groups = $groups_desired;
      $count = count($groups);
      $diff1 = array_diff($groups_desired, $groups);
      $diff2 = array_diff($groups, $groups_desired);
      $pass = (count($diff1) === 0 && count($diff2) === 0 && $count === $desired_count);
      $this->assertTrue($pass);

      // Test parent groupUserMembershipsFromUserAttr, for openldap should be
      // false, for ad should work.
      // TODO: Comment out.
      // $groups = $ldap_server->
      // groupUserMembershipsFromUserAttr($ldap_module_user_entry, $nested);.
      $count = is_array($groups) ? count($groups) : $count;
      $pass = (count($diff1) === 0 && count($diff2) === 0 && $count === $desired_count);
      $this->assertTrue($pass);

      // TODO: Comment out.
      // $groups = $ldap_server->
      // groupUserMembershipsFromEntry($ldap_module_user_entry, $nested);.
      $count = count($groups);
      $diff1 = array_diff($groups_desired, $groups);
      $diff2 = array_diff($groups, $groups_desired);
      $pass = (count($diff1) === 0 && count($diff2) === 0 && $count === $desired_count);
      $this->assertTrue($pass);

    }
  }

}
