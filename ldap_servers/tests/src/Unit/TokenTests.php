<?php

namespace Drupal\Tests\ldap_servers\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\ldap_servers\TokenHelper;
use Drupal\Tests\UnitTestCase;
use Drupal\user\Entity\User;

/**
 * @coversDefaultClass \Drupal\ldap_servers\TokenFunctions
 * @group ldap
 */
class TokenTests extends UnitTestCase {

  public $configFactory;
  public $container;

  protected function setUp() {
    parent::setUp();

    $this->config = $this->getMockBuilder('\Drupal\Core\Config\ImmutableConfig')
      ->disableOriginalConstructor()
      ->getMock();

    $this->configFactory = $this->getMockBuilder('\Drupal\Core\Config\ConfigFactory')
      ->disableOriginalConstructor()
      ->getMock();
    $this->configFactory->expects($this->any())
      ->method('get')
      ->with('ldap_help.settings')
      ->willReturn($this->config);

    // Create a dummy container.
    $this->container = new ContainerBuilder();
    $this->container->set('config.factory', $this->configFactory);
    \Drupal::setContainer($this->container);
  }

  public function testTokens() {
    
    // Test tokens, see http://drupal.org/node/1245736
    $ldap_entry = [
      'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
      'mail' => [0 => 'hpotter@hogwarts.edu', 'count' => 1],
      'sAMAccountName' => [0 => 'hpotter', 'count' => 1],
      'house' => [0 => 'Gryffindor', 1 => 'Privet Drive', 'count' => 2],
      'guid' => [0 => 'sdafsdfsdf', 'count' => 1],
      'count' => 3,
    ];

    $tokenHelper = new TokenHelper();

    $dn = $tokenHelper->tokenReplace($ldap_entry, '[dn]');
    $this->assertEquals($ldap_entry['dn'], $dn);

    $house0 = $tokenHelper->tokenReplace($ldap_entry, '[house:0]');
    $this->assertEquals($ldap_entry['house'][0], $house0);

    $mixed = $tokenHelper->tokenReplace($ldap_entry, 'thisold[house:0]');
    $this->assertEquals('thisold' . $ldap_entry['house'][0], $mixed);

    $compound = $tokenHelper->tokenReplace($ldap_entry, '[samaccountname:0][house:0]');
    $this->assertEquals($ldap_entry['sAMAccountName'][0] . $ldap_entry['house'][0], $compound);

    $literalvalue = $tokenHelper->tokenReplace($ldap_entry, 'literalvalue');
    $this->assertEquals('literalvalue', $literalvalue);

    $house0 = $tokenHelper->tokenReplace($ldap_entry, '[house]');
    $this->assertEquals($ldap_entry['house'][0], $house0);

    $house1 = $tokenHelper->tokenReplace($ldap_entry, '[house:last]');
    $this->assertEquals($ldap_entry['house'][1], $house1);

    $sAMAccountName = $tokenHelper->tokenReplace($ldap_entry, '[samaccountname:0]');
    $this->assertEquals($ldap_entry['sAMAccountName'][0], $sAMAccountName);

    $sAMAccountNameMixedCase = $tokenHelper->tokenReplace($ldap_entry, '[sAMAccountName:0]');
    $this->assertEquals($ldap_entry['sAMAccountName'][0], $sAMAccountNameMixedCase);

    $sAMAccountName2 = $tokenHelper->tokenReplace($ldap_entry, '[samaccountname]');
    $this->assertEquals($ldap_entry['sAMAccountName'][0], $sAMAccountName2);

    $sAMAccountName3 = $tokenHelper->tokenReplace($ldap_entry, '[sAMAccountName]');
    $this->assertEquals($ldap_entry['sAMAccountName'][0], $sAMAccountName3);

    $base64encode = $tokenHelper->tokenReplace($ldap_entry, '[guid;base64_encode]');
    $this->assertEquals(base64_encode($ldap_entry['guid'][0]), $base64encode);

    $bin2hex = $tokenHelper->tokenReplace($ldap_entry, '[guid;bin2hex]');
    $this->assertEquals(bin2hex($ldap_entry['guid'][0]), $bin2hex);

    $msguid = $tokenHelper->tokenReplace($ldap_entry, '[guid;msguid]');
    $this->assertEquals($tokenHelper->convertMsguidToString($ldap_entry['guid'][0]), $msguid);

    $binary = $tokenHelper->tokenReplace($ldap_entry, '[guid;binary]');
    $this->assertEquals($tokenHelper->binaryConversiontoString($ldap_entry['guid'][0]), $binary);

    $nameReplacement = $tokenHelper->tokenReplace($ldap_entry, '[property.name]', 'user_account');
    $this->assertEquals($ldap_entry['sAMAccountName'][0], $nameReplacement);
  }

}