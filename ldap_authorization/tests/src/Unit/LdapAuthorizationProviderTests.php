<?php

namespace Drupal\Tests\ldap_authorization\Unit;

use Drupal\authorization\Form\SubFormState;
use Drupal\Core\Form\FormState;
use Drupal\ldap_authorization\Plugin\authorization\Provider\LDAPAuthorizationProvider;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\ldap_authorization\Plugin\authorization\Provider\LDAPAuthorizationProvider
 * @group authorization
 */
class LdapAuthorizationProviderTests extends UnitTestCase {

  /**
   * Provider plugin.
   *
   * @var \Drupal\ldap_authorization\Plugin\authorization\Provider\LDAPAuthorizationProvider
   */
  protected $providerPlugin;

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    $this->providerPlugin = $this->getMockBuilder(LDAPAuthorizationProvider::class)
      ->disableOriginalConstructor()
      ->setMethods(NULL)
      ->getMock();
  }

  /**
   * Test regex validation().
   */
  public function testValidateRowForm() {

    $form_state = new FormState();
    $mappings = [
      0 => [
        'provider_mappings' => [
          'is_regex' => 1,
          'query' => 'example',
        ],
      ],
      1 => [
        'provider_mappings' => [
          'is_regex' => 1,
          'query' => '/.*/',
        ],
      ],
      2 => [
        'provider_mappings' => [
          'is_regex' => 0,
          'query' => '/.*/',
        ],
      ],
    ];
    $form_state->setUserInput($mappings);
    $sub_form_state = new SubFormState($form_state, ['provider_config']);
    $form = [];
    $this->providerPlugin->validateRowForm($form, $sub_form_state);
    $this->assertArrayEquals([], $sub_form_state->getErrors());
    // TODO: Still needs more useful assertions here.
  }

}
