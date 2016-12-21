<?php

namespace Drupal\Tests\ldap_user\Unit;

use Drupal\ldap_servers\TokenHelper;
use Drupal\ldap_user\LdapUserConf;
use Drupal\Tests\UnitTestCase;


/**
 * @coversDefaultClass \Drupal\ldap_user\LdapUserConf
 * @group ldap
 */
class LdapUserConfTests extends UnitTestCase {


  protected function setUp() {
    parent::setUp();
  }

  public function testUserExclusion() {

    /* Disallow user 1 */
    $account = $this->prophesize('\Drupal\user\Entity\User');
    $account->id()->willReturn(1);
    $this->assertTrue(LdapUserConf::excludeUser($account->reveal()));

    /* Disallow checkbox exclusion (everyone else allowed). */
    $account = $this->prophesize('\Drupal\user\Entity\User');
    $account->id()->willReturn(2);
    $value = new \stdClass;
    $value->value = 1;
    $account->get('ldap_user_ldap_exclude')->willReturn($value);
    $this->assertTrue(LdapUserConf::excludeUser($account->reveal()));

    /* Everyone else allowed. */
    $account = $this->prophesize('\Drupal\user\Entity\User');
    $account->id()->willReturn(2);
    $value = new \stdClass;
    $value->value = '';
    $account->get('ldap_user_ldap_exclude')->willReturn($value);
    $this->assertFalse(LdapUserConf::excludeUser($account->reveal()));

  }

}