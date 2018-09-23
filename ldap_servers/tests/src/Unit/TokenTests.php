<?php

namespace Drupal\Tests\ldap_servers\Unit;

use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\Ldap\Entry;

/**
 * Helper class to make it possible to simulate ldap_explode_dn().
 */
class LdapExplodeDnMock {

  /**
   * Simulate explode_dn.
   *
   * @return array
   *   DN exploded, input ignored.
   */
  public static function ldapExplodeDn($input) {
    return [
      'count' => 4,
      0 => 'cn=hpotter',
      1 => 'ou=Gryffindor',
      2 => 'ou=student',
      3 => 'ou=people',
      4 => 'dc=hogwarts',
      5 => 'dc=edu',
    ];
  }

}

/**
 * @coversDefaultClass \Drupal\ldap_servers\Processor\TokenProcessor
 * @group ldap
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class TokenTests extends UnitTestCase {

  public $serverFactory;
  public $config;
  public $container;

  /**
   * @var \Symfony\Component\Ldap\Entry
   */
  private $ldapEntry;
  protected $detailLog;
  protected $fileSystem;

  /**
   * Test setup.
   */
  protected function setUp() {
    parent::setUp();

    // TODO: Move the mock into the token class (was converted to trait.)
    class_alias(
      '\Drupal\Tests\ldap_servers\Unit\LdapExplodeDnMock',
      '\Drupal\ldap_servers\Entity\Server',
      TRUE
    );

    $this->ldapEntry = new Entry('cn=hpotter,ou=Gryffindor,ou=student,ou=people,dc=hogwarts,dc=edu', [
      'mail' => ['hpotter@hogwarts.edu'],
      'sAMAccountName' => ['hpotter'],
      'house' => ['Gryffindor', 'Privet Drive'],
      'guid' => ['sdafsdfsdf'],
    ]);
  }

  /**
   * Test the replacement of tokens.
   *
   * See http://drupal.org/node/1245736 for test tokens.
   */
  public function testTokenReplacement() {

    $tokenHelper = $this->getMockBuilder('\Drupal\ldap_servers\Processor\TokenProcessor')
      ->setMethods(NULL)
      ->disableOriginalConstructor()
      ->getMock();

    $dn = $tokenHelper->tokenReplace($this->ldapEntry, '[dn]');
    $this->assertEquals($this->ldapEntry->getDn(), $dn);

    $house0 = $tokenHelper->tokenReplace($this->ldapEntry, '[house:0]');
    $this->assertEquals($this->ldapEntry->getAttribute('house')[0], $house0);

    $mixed = $tokenHelper->tokenReplace($this->ldapEntry, 'thisold[house:0]');
    $this->assertEquals('thisold' . $this->ldapEntry->getAttribute('house')[0], $mixed);

    $compound = $tokenHelper->tokenReplace($this->ldapEntry, '[samaccountname:0][house:0]');
    // TODO: Expected :'hpotterGryffindor', Actual:'[samaccountname:0]Gryffindor'
    // $this->assertEquals($this->ldapEntry->getAttribute('sAMAccountName')[0] . $this->ldapEntry->getAttribute('house')[0], $compound);.
    $literalValue = $tokenHelper->tokenReplace($this->ldapEntry, 'literalvalue');
    $this->assertEquals('literalvalue', $literalValue);

    $house0 = $tokenHelper->tokenReplace($this->ldapEntry, '[house]');
    $this->assertEquals($this->ldapEntry->getAttribute('house')[0], $house0);

    $houseLast = $tokenHelper->tokenReplace($this->ldapEntry, '[house:last]');
    $this->assertEquals($this->ldapEntry->getAttribute('house')[1], $houseLast);

    $sAMAccountName = $tokenHelper->tokenReplace($this->ldapEntry, '[samaccountname:0]');
    // TODO: Expected :'hpotter', Actual: NULL
    // $this->assertEquals($this->ldapEntry->getAttribute('sAMAccountName')[0], $sAMAccountName);.
    $sAMAccountNameMixedCase = $tokenHelper->tokenReplace($this->ldapEntry, '[sAMAccountName:0]');
    // TODO: Expected :'hpotter', Actual: NULL
    // $this->assertEquals($this->ldapEntry->getAttribute('sAMAccountName')[0], $sAMAccountNameMixedCase);.
    $sAMAccountName2 = $tokenHelper->tokenReplace($this->ldapEntry, '[samaccountname]');
    // TODO: Expected :'hpotter', Actual: NULL
    // $this->assertEquals($this->ldapEntry->getAttribute('sAMAccountName')[0], $sAMAccountName2);.
    $sAMAccountName3 = $tokenHelper->tokenReplace($this->ldapEntry, '[sAMAccountName]');
    // TODO: Expected :'hpotter', Actual: NULL
    // $this->assertEquals($this->ldapEntry->getAttribute('sAMAccountName')[0], $sAMAccountName3);.
    $base64encode = $tokenHelper->tokenReplace($this->ldapEntry, '[guid;base64_encode]');
    $this->assertEquals(base64_encode($this->ldapEntry->getAttribute('guid')[0]), $base64encode);

    $bin2hex = $tokenHelper->tokenReplace($this->ldapEntry, '[guid;bin2hex]');
    $this->assertEquals(bin2hex($this->ldapEntry->getAttribute('guid')[0]), $bin2hex);

    $msguid = $tokenHelper->tokenReplace($this->ldapEntry, '[guid;msguid]');
    $this->assertEquals(ConversionHelper::convertMsguidToString($this->ldapEntry->getAttribute('guid')[0]), $msguid);

    $binary = $tokenHelper->tokenReplace($this->ldapEntry, '[guid;binary]');
    $this->assertEquals(ConversionHelper::binaryConversionToString($this->ldapEntry->getAttribute('guid')[0]), $binary);

    $account = $this->prophesize('\Drupal\user\Entity\User');
    $value = new \stdClass();
    $value->value = $this->ldapEntry->getAttribute('sAMAccountName')[0];
    $account->get('name')->willReturn($value);
    $nameReplacement = $tokenHelper->tokenReplace($account->reveal(), '[property.name]', 'user_account');
    $this->assertEquals($this->ldapEntry->getAttribute('sAMAccountName')[0], $nameReplacement);

  }

  /**
   * Additional token tests for the reverse behaviour for DN derivatives.
   */
  public function testTokensReverse() {
    $tokenHelper = $this->getMockBuilder('\Drupal\ldap_servers\Processor\TokenProcessor')
      ->setMethods(NULL)
      ->disableOriginalConstructor()
      ->getMock();

    // Test regular reversal (2 elements) at beginning.
    $dc = $tokenHelper->tokenReplace($this->ldapEntry, '[dc:reverse:0]');
    $this->assertEquals('edu', $dc);

    // Test single element reversion.
    $ou = $tokenHelper->tokenReplace($this->ldapEntry, '[cn:reverse:0]');
    $this->assertEquals('hpotter', $ou);

    // Test 3 element reversion at end.
    $ou2 = $tokenHelper->tokenReplace($this->ldapEntry, '[ou:reverse:2]');
    $this->assertEquals('Gryffindor', $ou2);

  }

}
