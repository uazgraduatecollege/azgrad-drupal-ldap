<?php

namespace Drupal\Tests\ldap_servers\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\ldap_servers\PRocessor\TokenProcessor
 * @group ldap
 */
class TokenTests extends UnitTestCase {

  public $configFactory;
  public $serverFactory;
  public $config;
  public $container;

  /**
   * Test setup.
   */
  protected function setUp() {
    parent::setUp();

    /* Mocks the configuration due to detailed watchdog logging. */
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

    /* Mocks the Server due to wrapper for ldap_explode_dn(). */
    $this->serverFactory = $this->getMockBuilder('\Drupal\ldap_servers\Entity\Server')
      ->disableOriginalConstructor()
      ->getMock();

    $this->serverFactory->expects($this->any())
      ->method('ldapExplodeDn')
      ->willReturn([
        'count' => 4,
        0 => 'cn=hpotter',
        1 => 'ou=people',
        2 => 'dc=hogwarts',
        3 => 'dc=edu',
      ]);

    $this->container = new ContainerBuilder();
    $this->container->set('config.factory', $this->configFactory);
    $this->container->set('ldap.servers', $this->serverFactory);
    \Drupal::setContainer($this->container);
  }

  /**
   * Test the replacement of tokens.
   *
   * See http://drupal.org/node/1245736 for test tokens.
   */
  public function testTokenReplacement() {

    $ldap_entry = [
      'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
      'mail' => [0 => 'hpotter@hogwarts.edu', 'count' => 1],
      'sAMAccountName' => [0 => 'hpotter', 'count' => 1],
      'house' => [0 => 'Gryffindor', 1 => 'Privet Drive', 'count' => 2],
      'guid' => [0 => 'sdafsdfsdf', 'count' => 1],
      'count' => 3,
    ];

    $tokenHelper = new TokenProcessor();

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
    $this->assertEquals($tokenHelper->binaryConversionToString($ldap_entry['guid'][0]), $binary);

    $account = $this->prophesize('\Drupal\user\Entity\User');
    $value = new \stdClass();
    $value->value = $ldap_entry['sAMAccountName'][0];
    $account->get('name')->willReturn($value);
    $nameReplacement = $tokenHelper->tokenReplace($account->reveal(), '[property.name]', 'user_account');
    $this->assertEquals($ldap_entry['sAMAccountName'][0], $nameReplacement);

  }

  /**
   * Test the temporary storage of passwords.
   */
  public function testPasswordStorage() {
    $password = 'my-pass';

    // Verify storage.
    $tokenHelperA = new TokenProcessor();
    $tokenHelperA::passwordStorage('set', $password);
    $this->assertEquals($password, $tokenHelperA::passwordStorage('get'));

    // Verify storage across instance.
    $tokenHelperB = new TokenProcessor();
    $this->assertEquals($password, $tokenHelperB::passwordStorage('get'));

    // Verify storage without instance.
    $this->assertEquals($password, TokenProcessor::passwordStorage('get'));

    // Unset storage.
    TokenProcessor::passwordStorage('set', NULL);
    $this->assertEquals(NULL, TokenProcessor::passwordStorage('get'));
  }

}
