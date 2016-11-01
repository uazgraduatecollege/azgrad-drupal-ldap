<?php

namespace Drupal\Tests\ldap_servers\Unit;

use Drupal\ldap_servers\Entity\Server;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\ldap_servers\Entity\Server
 * @group ldap
 */
class ServerTests extends UnitTestCase {

  /**
   *
   */
  public function testSearchAllBaseDns() {

    $stub = $this->getMockBuilder(Server::class)
      ->disableOriginalConstructor()
      ->getMock();

    $stub->method('getBasedn')
      ->willReturn([0 => ['ou' => 'people', 'dc' => 'example', 'dc' => 'org']]);
    $stub->method('search')
      ->willReturn([
        'count' => 1,
        0 => [
          'objectclass' => [
            'count' => 4,
            '0' => 'organizationalPerson',
            '1' => 'Person',
            '2' => 'inetOrgPerson',
          ],
        ],
      ]);
    // TODO: Figure out the correct format to pass to searchAllBaseDns and compare them.
    // $stub->searchAllBaseDns('*');.
    $this->assertTrue(TRUE);
  }

  /**
   *
   */
  public function testRemoveUnchangedAttributes() {

    $existing_data = [
      'count' => 1,
      ['organizationalPerson', 'Person', 'inetOrgPerson'],
    ];

    $new_data = [
      0 => 'organizationalPersonUpdated',
      1 => 'Person',
    ];
    // TODO: Figure out the correct format to RemoveUnchangedAttributes and compare them.
    // $result = Server::removeUnchangedAttributes($new_data, $existing_data);.
    $this->assertTrue(TRUE);
  }

}
