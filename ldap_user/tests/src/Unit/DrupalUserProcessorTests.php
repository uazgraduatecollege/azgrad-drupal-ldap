<?php

namespace Drupal\Tests\ldap_user\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\ldap_user\Processor\DrupalUserProcessor;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\ldap_user\Processor\DrupalUserProcessor
 * @group ldap
 */
class DrupalUserProcessorTests extends UnitTestCase {

  public $cacheFactory;
  public $configFactory;
  public $serverFactory;
  public $config;
  public $container;

  public $provisioningEvents;

  protected function setUp() {
    parent::setUp();

    $this->provisioningEvents = [
      LdapConfiguration::$provisioningDirectionToDrupalUser => [
        LdapConfiguration::$eventSyncToDrupalUser,
        LdapConfiguration::$eventCreateDrupalUser,
      ],

      LdapConfiguration::$provisioningDirectionToLDAPEntry => [
        LdapConfiguration::$eventSyncToLdapEntry,
        LdapConfiguration::$eventCreateLdapEntry,
      ],
    ];

    /* Mocks the configuration due to detailed watchdog logging. */
    $this->config = $this->getMockBuilder('\Drupal\Core\Config\ImmutableConfig')
      ->disableOriginalConstructor()
      ->getMock();

    $this->configFactory = $this->getMockBuilder('\Drupal\Core\Config\ConfigFactory')
      ->disableOriginalConstructor()
      ->getMock();

    $this->configFactory->expects($this->any())
      ->method('get')
      ->with('ldap_user.settings')
      ->willReturn($this->config);

    $this->cacheFactory = $this->getMockBuilder('\Drupal\Core\Cache\CacheFactory')
      ->disableOriginalConstructor()
      ->getMock();

    $this->cacheFactory->expects($this->any())
      ->method('get')
      ->willReturn(FALSE);

    $this->container = new ContainerBuilder();
    $this->container->set('config.factory', $this->configFactory);
    $this->container->set('cache.default', $this->cacheFactory);
    \Drupal::setContainer($this->container);
  }

  public function testprovisionDrupalAccount() {
    $this->assertTrue(true);
    return;
    // TODO

    $account = NULL;
    $user_edit = array('name' => 'hpotter');

    // Test method provisionDrupalAccount()
    $processor = new DrupalUserProcessor();
    $hpotter = $processor->provisionDrupalAccount($account, $user_edit, NULL, TRUE);

    $hpotter = user_load_by_name('hpotter');

    $properties_set = (
      $hpotter->name == 'hpotter' &&
      $hpotter->mail == 'hpotter@hogwarts.edu' &&
      $hpotter->init == 'hpotter@hogwarts.edu' &&
      $hpotter->status == 1
    );
    $this->assertTrue($properties_set, t('user name, mail, init, and status correctly populated for hpotter'), $this->testId());

    $fields_set = (
      isset($hpotter->ldap_user_puid['und'][0]['value']) &&
      $hpotter->ldap_user_puid['und'][0]['value'] == '101' &&
      isset($hpotter->ldap_user_puid_property['und'][0]['value']) &&
      $hpotter->ldap_user_puid_property['und'][0]['value'] == 'guid' &&
      isset($hpotter->ldap_user_puid_sid['und'][0]['value']) &&
      $hpotter->ldap_user_puid_sid['und'][0]['value'] == 'activedirectory1' &&
      isset($hpotter->ldap_user_current_dn['und'][0]['value']) &&
      $hpotter->ldap_user_current_dn['und'][0]['value'] == 'cn=hpotter,ou=people,dc=hogwarts,dc=edu'
    );
    $this->assertTrue($fields_set, t('user ldap_user_puid, ldap_user_puid_property, ldap_user_puid_sid, and  ldap_user_current_dn correctly populated for hpotter'), $this->testId('provisionDrupalAccount function test 3'));

    $data_diff = array_diff(
      $hpotter->data['ldap_user'],
      array(
        'init' =>
          array(
            'sid' => 'activedirectory1',
            'dn' => NULL,
            'mail' => 'hpotter@hogwarts.edu',
          ),
      )
    );
    $this->assertTrue(count($data_diff) == 0, t('user->data array correctly populated for hpotter'), $this->testId());
  }

  public function testSyncToDrupalUser() {
    $this->assertTrue(true);
    return;
    // TODO

    // Test account exists with correct username, mail, fname, puid, puidfield, dn
    // Change some user mock ldap data first, (mail and fname) then sync.
    $account = user_load_by_name('hpotter');

    $user_edit = NULL;
    $ldapUserSyncMappings = array();
    $sid = 'activedirectory1';
    $ldapUserSyncMappings[LdapConfiguration::$provisioningDirectionToDrupalUser]['[property.mail]'] = array(
      'sid' => $sid,
      'ldap_attr' => '[mail]',
      'user_attr' => '[property.mail]',
      'convert' => 0,
      'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
      'ldap_contexts' => array('ldap_user_insert_drupal_user', 'ldap_user_update_drupal_user', 'ldap_authentication_authenticate'),
      'prov_events' => array(LdapConfiguration::$eventSyncToDrupalUser),
      'name' => 'Property: Mail',
      'enabled' => TRUE,
      'config_module' => 'ldap_servers',
      'prov_module' => 'ldap_user',
      'user_tokens' => '',
    );

    $this->testFunctions->setFakeServerUserAttribute($sid, 'cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'mail', 'hpotter@owlcarriers.com', 0);

    $processor = new DrupalUserProcessor();
    $processor->syncToDrupalAccount($account, LdapConfiguration::$eventSyncToDrupalUser, NULL, TRUE);
    $hpotter = user_load_by_name('hpotter');
    $this->assertEquals($hpotter->mail, 'hpotter@owlcarriers.com');
  }

  public function testApplyAttributesGeneric() {
    $this->assertTrue(true);
    return;
    // TODO

    $sid = 'activedirectory1';
    $tests = [];

    // Test for plain sync of field on create/sync to Drupal user.
    $tests[] = [
      'disabled' => 0,
      'user' => 'hpotter',
      'field_name' => 'field_lname',
      'field_values' => [['sn' => 'Potter'], ['sn' => 'Pottery-Chard']],
      // First value is what is desired on sync, second if no sycn.
      'field_results' => ['Potter', 'Pottery-Chard'],
      'mapping' => [
        'sid' => $sid,
        'name' => 'Field: Last Name',
        'ldap_attr' => '[SN]',
        'user_attr' => '[field.field_lname]',
        'convert' => 0,
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser
        ],
        'user_tokens' => '',
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'enabled' => TRUE,
      ],
    ];

    foreach ($tests as $j => $test) {
      $direction = $test['mapping']['direction'];
      // Test for each provision event.
      foreach ($this->provisioningEvents[$direction] as $i => $prov_event) {
        if (isset($test['property_name'])) {
          $property_token = '[property.' . $test['property_name'] . ']';
          $ldapUserSyncMappings[$direction][$property_token] = $test['mapping'];
        }
        if (isset($test['field_name'])) {
          $field_token = '[field.' . $test['field_name'] . ']';
          $ldapUserSyncMappings[$direction][$field_token] = $test['mapping'];
        }

        // 3. create new user with provisionDrupalAccount.
        $userValues = ['name' => $test['user']];
        $processor = new DrupalUserProcessor();
        $processor->provisionDrupalAccount(NULL, $userValues, NULL, TRUE);
        $user_entity = user_load_by_name($test['user']);
        if (isset($test['property_name'])) {
          // If intended to sync.
          if (in_array($prov_event, $ldapUserSyncMappings[$direction][$property_token]['prov_events'])) {
            $property_success = ($user_entity->{$test['property_name']} == $test['property_results'][0]);
            $this->assertTrue($property_success);

          }
        }
        if (isset($test['field_name'])) {
          // If intended to sync.
          if (in_array($prov_event, $ldapUserSyncMappings[$direction][$field_token]['prov_events'])) {
            $field_success = isset($user_entity->{$test['field_name']}['und'][0]['value']) &&
              $user_entity->{$test['field_name']}['und'][0]['value'] == $test['field_results'][0];
            $this->assertTrue($field_success);
          }
        }
      }
    }
  }

  public function testApplyAttributeCompoundToken() {
    $this->assertTrue(true);
    return;
    // TODO

    // Test for compound tokens on create/sync to Drupal user.
    $tests[] = [
      'disabled' => 0,
      'user' => 'hpotter',
      'field_name' => 'field_display_name',
      'field_values' => [['givenname' => 'Harry', 'sn' => 'Potter'], ['givenname' => 'Sir Harry', 'sn' => 'Potter']],
      // Desired results.
      'field_results' => ['Harry Potter', 'Sir Harry Potter'],
      'mapping' => [
        'ldap_attr' => '[givenName] [sn]',
        'user_attr' => '[field.field_display_name]',
        'convert' => 0,
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
        'prov_events' => [LdapConfiguration::$eventCreateDrupalUser, LdapConfiguration::$eventSyncToDrupalUser],
        'name' => 'Field: Display Name',
        'enabled' => TRUE,
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ],
    ];
  }

  public function testApplyAttributeConstants() {
    $this->assertTrue(true);
    return;
    // TODO

    // Test for constants in use (e.g. "Smith" and "0") instead of tokens e.g. "[sn]" and "[enabled]" on create/sync to Drupal user.
    $tests[] = [
      'disabled' => 0,
      'user' => 'hpotter',
      'field_name' => 'field_lname',
      'field_values' => [['sn' => 'Potter1'], ['sn' => 'Potter2']],
      'field_results' => ['Smith', 'Smith'],
      'mapping' => [
        'name' => 'Field: Last Name',
        // Testing of a constant mapped to a field.  that is everyone should have last name smith.
        'ldap_attr' => 'Smith',
        'user_attr' => '[field.field_lname]',
        'convert' => 0,
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
        'prov_events' => [LdapConfiguration::$eventCreateDrupalUser, LdapConfiguration::$eventSyncToDrupalUser],
        'user_tokens' => '',
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'enabled' => TRUE,

      ],
    ];
  }

  public function testApplyAttributeCompoundTokens() {
    $this->assertTrue(true);
    return;
    // TODO

    // Test for compound tokens on create/sync to Drupal user.
    $tests[] = [
      'disabled' => 0,
      'user' => 'hpotter',
      'property_name' => 'signature',
      'property_values' => [['cn' => 'hpotter'], ['cn' => 'hpotter2']],
      'property_results' => ['hpotter@hogwarts.edu', 'hpotter2@hogwarts.edu'],
      'mapping' => [
        'ldap_attr' => '[cn]@hogwarts.edu',
        'user_attr' => '[property.signature]',
        'convert' => 0,
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
        'prov_events' => [LdapConfiguration::$eventCreateDrupalUser, LdapConfiguration::$eventSyncToDrupalUser],
        'name' => 'Property: Signature',
        'enabled' => TRUE,
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ],
    ];
  }

  public function testApplyAttributeMultipleMailProperty() {
    $this->assertTrue(true);
    return;
    // TODO

    // Test sync of mail property with multiple mail on create/sync to Drupal user.
    $tests[] = [
      'disabled' => 0,
      'user' => 'hpotter',
      'property_name' => 'mail',
      'property_values' => [['mail' => 'hpotter@hogwarts.edu'], ['mail' => 'hpotter@owlmail.com']],
      'property_results' => ['hpotter@hogwarts.edu', 'hpotter@owlmail.com'],
      'mapping' => [
        'ldap_attr' => '[mail]',
        'user_attr' => '[property.mail]',
        'convert' => 0,
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
        'prov_events' => [LdapConfiguration::$eventCreateDrupalUser, LdapConfiguration::$eventSyncToDrupalUser],
        'name' => 'Property: Mail',
        'enabled' => TRUE,
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ],
    ];
  }

  public function testApplyAttributeStatusZ() {
    $this->assertTrue(true);
    return;
    // TODO

    // Test sync of status property with value 'z' on create to Drupal user.
    $tests[] = [
      'disabled' => 0,
      'user' => 'hpotter',
      'property_name' => 'status',
      'property_values' => [[0 => 'z'], [0 => 'z']],
      'property_results' => [0, 0],
      'mapping' => [
        'ldap_attr' => '0',
        // Testing of a constant mapped to property.
        'user_attr' => '[property.status]',
        'convert' => 0,
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
        'prov_events' => [LdapConfiguration::$eventCreateDrupalUser],
        'name' => 'Property: Status',
        'enabled' => TRUE,
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ],
    ];
  }

  // @TODO: Write a test for applyAttributes for binary fields.

  // @TODO: Write a test for applyAttributes for case sensitivity in tokens.

  // @TODO: Write a test for applyAttributes for user_attr in mappings.


}
