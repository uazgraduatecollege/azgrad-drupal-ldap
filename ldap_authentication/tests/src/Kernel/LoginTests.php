<?php

namespace Drupal\Tests\ldap_authentication\Kernel;

use Drupal\Core\Form\FormState;
use Drupal\ldap_authentication\Controller\LoginValidatorLoginForm;
use Drupal\Tests\token\Kernel\KernelTestBase;

/**
 * Login tests.
 *
 * @group ldap
 */
class LoginTests extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  public static $modules = [
    'externalauth',
    'ldap_servers',
    'ldap_authentication',
  ];

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();

    $this->installConfig('ldap_authentication');
  }

  /**
   * Test mixed user mode.
   */
  public function testMixedUserMode() {

    $validator = new LoginValidatorLoginForm(
      $this->container->get('config.factory'),
      $this->container->get('ldap.detail_log'),
      $this->container->get('logger.channel.ldap_authentication'),
      $this->container->get('entity_type.manager'),
      $this->container->get('module_handler'),
      $this->container->get('ldap.bridge'),
      $this->container->get('externalauth.authmap'),
      $this->container->get('ldap_authentication.servers'),
      $this->container->get('ldap.user_manager'),
      $this->container->get('messenger'),
    );

    $form_state = new FormState();
    $form_state->set('name', 'hpotter');
    $form_state->set('pass', 'pass');
    $state = $validator->validateLogin($form_state);
    $errors = $state->getErrors();
    $error = reset($errors);
    self::markTestIncomplete('TODO: Write test, currently stuck at missing server.');
    self::assertCount(0, $state->getErrors(), $error);
    // Assert right credentials LDAP, see example data.
  }

  /**
   * Test exclusive user mode.
   */
  public function testExclusiveUserMode() {
    $this->markTestIncomplete('Test missing.');
    // TODO: Write test
    // assert right credentials LDAP
    // assert local Drupal user without mapping (associated, not associated)
    // see example data.
  }

  /**
   * Test SSO validation.
   */
  public function testSsoValidation() {
    $this->markTestIncomplete('Test missing.');
    // TODO: Write test
    // assert right credentials LDAP
    // assert wrong credentials (i.e. password random as it should be)
    // assert local Drupal user without mapping (associated, not associated)
    // test exclusive/mixed
    // see example data.
    // consider moving to ldap_sso.
  }

  /**
   * Test the whitelist.
   */
  public function testWhiteList() {
    $this->markTestIncomplete('Test missing.');
    // TODO: Write test
    // one value, two values, zero values
    // logon with whitelisted and w/o.
  }

  /**
   * Test the blacklist.
   */
  public function testBlacklist() {
    $this->markTestIncomplete('Test missing.');
    // TODO: Write test
    // one value, two values, zero values
    // logon with blacklisted and w/o.
  }

}
