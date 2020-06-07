<?php

declare(strict_types = 1);

namespace Drupal\Tests\ldap_authorization\Unit;

use Drupal\authorization\Form\SubFormState;
use Drupal\Core\Form\FormState;
use Drupal\ldap_authorization\Plugin\authorization\Provider\LDAPAuthorizationProvider;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\ldap_authorization\Plugin\authorization\Provider\LDAPAuthorizationProvider
 * @group authorization
 */
class LdapAuthorizationProviderTest extends UnitTestCase {

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
  public function testValidateRowForm(): void {

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

  /**
   * Test the filter proposal.
   */
  public function testFilterProposal(): void {

    // Example of groups defined in.
    $input = [
      'cn=students',
    ];

    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => 'cn=students',
        'is_regex' => FALSE,
      ])
    );

    $input = [
      'cn=students,ou=groups,dc=hogwarts,dc=edu',
      'cn=gryffindor,ou=groups,dc=hogwarts,dc=edu',
      'cn=users,ou=groups,dc=hogwarts,dc=edu',
    ];

    $this->assertCount(
      0,
      $this->providerPlugin->filterProposals($input, [
        'query' => 'cn=students',
        'is_regex' => FALSE,
      ])
    );

    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => 'cn=students,ou=groups,dc=hogwarts,dc=edu',
        'is_regex' => FALSE,
      ])
    );
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => 'CN=students,ou=groups,dc=hogwarts,dc=edu',
        'is_regex' => FALSE,
      ])
    );
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => '/cn=students/i',
        'is_regex' => TRUE,
      ])
    );
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => '/CN=students/i',
        'is_regex' => TRUE,
      ])
    );

    $input = [
      'memberOf=students,ou=groups,dc=hogwarts,dc=edu',
    ];
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => 'memberOf=students,ou=groups,dc=hogwarts,dc=edu',
        'is_regex' => FALSE,
      ])
    );
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => 'memberof=students,ou=groups,dc=hogwarts,dc=edu',
        'is_regex' => FALSE,
      ])
    );
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => '/^memberof=students/i',
        'is_regex' => TRUE,
      ])
    );
    $this->assertCount(
      1,
      $this->providerPlugin->filterProposals($input, [
        'query' => '/^memberOf=students/i',
        'is_regex' => TRUE,
      ])
    );
    $this->assertCount(
      0,
      $this->providerPlugin->filterProposals($input, [
        'query' => '/^emberOf=students/i',
        'is_regex' => TRUE,
      ])
    );
  }

}
