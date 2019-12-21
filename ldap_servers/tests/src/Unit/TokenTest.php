<?php

declare(strict_types=1);

namespace Drupal\Tests\ldap_servers\Unit;

use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\Ldap\Entry;
use Drupal\ldap_servers\Processor\TokenProcessor;

/**
 * @coversDefaultClass \Drupal\ldap_servers\Processor\TokenProcessor
 * @group ldap
 */
class TokenTest extends UnitTestCase {

  /**
   * LDAP Entry.
   *
   * @var \Symfony\Component\Ldap\Entry
   */
  private $ldapEntry;

  /**
   * TokenProcessor.
   *
   * @var \Drupal\ldap_servers\Processor\TokenProcessor
   */
  private $processor;

  /**
   * Test setup.
   */
  protected function setUp() {
    parent::setUp();

    $this->ldapEntry = new Entry('cn=hpotter,ou=Gryffindor,ou=student,ou=people,dc=hogwarts,dc=edu', [
      'mail' => ['hpotter@hogwarts.edu'],
      'sAMAccountName' => ['hpotter'],
      'house' => ['Gryffindor', 'Privet Drive'],
      'guid' => ['sdafsdfsdf'],
    ]);
    $this->processor = $this->getMockBuilder(TokenProcessor::class)
      ->setMethods(NULL)
      ->disableOriginalConstructor()
      ->getMock();
  }

  /**
   * Test the replacement of tokens.
   *
   * See http://drupal.org/node/1245736 for test tokens.
   */
  public function testTokenReplacement() {
    $literalValue = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, 'literalvalue');
    $this->assertEquals('literalvalue', $literalValue);

    $dn = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[dn]');
    $this->assertEquals($this->ldapEntry->getDn(), $dn);

    $house0 = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[house:0]');
    $this->assertEquals('Gryffindor', $house0);
    $house_noindex = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[house]');
    $this->assertEquals('Gryffindor', $house_noindex);

    $houseLast = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[house:last]');
    $this->assertEquals('Privet Drive', $houseLast);

    $mixed = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, 'thisold[house:0]');
    $this->assertEquals('thisoldGryffindor', $mixed);

    $compound = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[sAMAccountName:0][house:0]');
    $this->assertEquals('hpotterGryffindor', $compound);
  }

  /**
   * Test case sensitive issues.
   */
  public function testTokenReplacementCaseSensitivity(): void {
    $sAMAccountName = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[samaccountname:0]');
    $this->assertEquals('hpotter', $sAMAccountName);
    $sAMAccountNameMixedCase = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[sAMAccountName:0]');
    $this->assertEquals('hpotter', $sAMAccountNameMixedCase);
    $sAMAccountName2 = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[samaccountname]');
    $this->assertEquals('hpotter', $sAMAccountName2);
    $sAMAccountName3 = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[sAMAccountName]');
    $this->assertEquals('hpotter', $sAMAccountName3);
  }

  /**
   * Test binary conversion.
   */
  public function testBinaryConversion(): void {
    $base64encode = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[guid;base64_encode]');
    $this->assertEquals(base64_encode('sdafsdfsdf'), $base64encode);

    $bin2hex = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[guid;bin2hex]');
    $this->assertEquals(bin2hex('sdafsdfsdf'), $bin2hex);

    $msguid = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[guid;msguid]');
    $this->assertEquals(ConversionHelper::convertMsguidToString('sdafsdfsdf'), $msguid);

    $binary = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[guid;binary]');
    $this->assertEquals(ConversionHelper::binaryConversionToString('sdafsdfsdf'), $binary);
  }

  /**
   * Test reversal.
   */
  public function testReversal(): void {
    // Test regular reversal (2 elements) at beginning.
    $dc = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[dc:reverse:0]');
    $this->assertEquals('edu', $dc);

    // Test single element reversion.
    $ou = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[cn:reverse:0]');
    $this->assertEquals('hpotter', $ou);

    // Test 3 element reversion at end.
    $ou2 = $this->processor->ldapEntryReplacementsForDrupalAccount($this->ldapEntry, '[ou:reverse:2]');
    $this->assertEquals('Gryffindor', $ou2);
  }

}
