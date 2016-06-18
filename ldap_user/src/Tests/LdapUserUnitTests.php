<?php
namespace Drupal\ldap_user\Tests;

use Drupal\Component\Utility\Unicode;
use Drupal\ldap_test\LdapTestCase;
use ReflectionFunction;

/**
 *
 */
class LdapUserUnitTests extends LdapTestCase {

  /**
   *
   */
  public static function getInfo() {
    return array(
      'name' => 'LDAP User Unit Tests',
      'description' => 'Test functions outside of real contexts.',
      'group' => 'LDAP User',
    );
  }

  /**
   *
   */
  function __construct($test_id = NULL) {
    parent::__construct($test_id);
  }

  public $module_name = 'ldap_user';
  protected $ldap_test_data;

  public static $modules = array('ldap_servers', 'ldap_authentication', 'ldap_authorization', 'ldap_user');

  /**
   * Create one or more server configurations in such as way
   *  that this setUp can be a prerequisite for ldap_authentication and ldap_authorization.
   *    * Function setUp() {
   * parent::setUp(array());
   * // @FIXME
   * // // @FIXME
   * // // This looks like another module's variable. You'll need to rewrite this call
   * // // to ensure that it uses the correct configuration object.
   * // variable_set('ldap_simpletest', 2);
   *    * }
   *    * function tearDown() {
   * parent::tearDown();
   * // @FIXME
   * // // @FIXME
   * // // This looks like another module's variable. You'll need to rewrite this call
   * // // to ensure that it uses the correct configuration object.
   * // variable_del('ldap_help_watchdog_detail');
   *    * // @FIXME
   * // // @FIXME
   * // // This looks like another module's variable. You'll need to rewrite this call
   * // // to ensure that it uses the correct configuration object.
   * // variable_del('ldap_simpletest');
   *    * }.
   */

  /**
   * Make sure install succeeds and ldap user functions/methods work.
   */
  function testUnitTests() {

    // Just to give warning if setup doesn't succeed.
    /* @FIXME
    // // This looks like another module's variable. You'll need to rewrite this call
    // // to ensure that it uses the correct configuration object.
    // $setup_success = (
    //         module_exists('ldap_user') &&
    //         module_exists('ldap_servers') &&
    //         (variable_get('ldap_simpletest', 2) > 0)
    );

    $this->assertTrue($setup_success, ' ldap_user setup successful', $this->testId('setup'));
     */
    $api_functions = array(
      'ldap_user_conf' => array(2, 0),
      'ldap_user_synch_to_drupal' => array(3, 1),
      'ldap_user_provision_to_drupal' => array(2, 1),
      'ldap_user_ldap_provision_semaphore' => array(4, 2),
      'ldap_user_token_replace' => array(3, 2),
      'ldap_user_token_tokenize_entry' => array(5, 2),
    );

    foreach ($api_functions as $api_function_name => $param_count) {
      $reflector = new ReflectionFunction($api_function_name);
      $this->assertTrue(
        function_exists($api_function_name) &&
        $param_count[1] == $reflector->getNumberOfRequiredParameters() &&
        $param_count[0] == $reflector->getNumberOfParameters(), ' api function ' . $api_function_name . ' parameters and required parameters count unchanged.', $this->testId($api_function_name . ' unchanged'));
    }

    $this->assertTrue(\Drupal::service("cron")->run(), t('Cron can run with ldap user enabled.'), $this->testId('cron works'));

    // Test user token functions.
    $entity = new stdClass();
    $entity->lname['und'][0]['value'] = 'potter';
    $entity->house['und'][0]['value'] = 'Gryffindor';
    $entity->house['und'][1]['value'] = 'Privet Drive';
    $account = new stdClass();
    $account->mail = 'hpotter@hogwarts.edu';
    $mail = ldap_user_token_replace('[property.mail]', $account, $entity);
    $this->assertTrue($mail == $account->mail, t('[property.mail] token worked on ldap_user_token_replace().'), $this->testId('tokens.property'));
    $lname = ldap_user_token_replace('[field.lname]', $account, $entity);
    $this->assertTrue($lname == $entity->lname['und'][0]['value'], t('[field.lname] token worked on ldap_user_token_replace().'), $this->testId('tokens.property.field'));
    $house1 = ldap_user_token_replace('[field.house:1]', $account, $entity);
    $this->assertTrue($house1 == $entity->house['und'][1]['value'], t('[field.house:1] token worked on ldap_user_token_replace().'), $this->testId('tokens.property.field.ordinal'));
    // @todo need tests for :last and a multivalued attribute.  see http://drupal.org/node/1245736

    $sids = array('activedirectory1');
    // prepTestData($sids, 'provisionToDrupal', 'default');.
    $this->prepTestData('hogwarts', $sids, 'default');
    $ldap_server = ldap_servers_get_servers('activedirectory1', NULL, TRUE, TRUE);
    $ldap_user_conf = ldap_user_conf('admin', TRUE);

    $this->assertTrue(is_object($ldap_user_conf), t('ldap_conf class instantiated'), $this->testId('construct ldapUserConf object'));

    $user_edit = array();
    $ldap_user = ldap_servers_get_user_ldap_data('hpotter', $ldap_user_conf->drupalAcctProvisionServer, 'ldap_user_prov_to_drupal');

    $desired_result = array(
      'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
      'mail' => 'hpotter@hogwarts.edu',
      'attr' => $ldap_server->entries['cn=hpotter,ou=people,dc=hogwarts,dc=edu'],
      'sid' => 'activedirectory1',
    );

    $array_diff = array_diff($ldap_user, $desired_result);
    $this->assertTrue(count($array_diff) == 0, t('ldap_servers_get_user_ldap_data retrieved correct attributes and values'), $this->testId('ldap_servers_get_user_ldap_data'));
    if (count($array_diff) != 0) {
      debug('ldap_servers_get_user_ldap_data failed.  resulting ldap data array:'); debug($ldap_user); debug('desired result:'); debug($desired_result); debug('array_diff:'); debug($array_diff);
    }
    $ldap_todrupal_prov_server = ldap_servers_get_servers($ldap_user_conf->drupalAcctProvisionServer, 'all', TRUE);
    $ldap_user_conf->entryToUserEdit($ldap_user, $user_edit, $ldap_todrupal_prov_server);

    unset($user_edit['pass']);
    $desired_result = array(
      'mail' => 'hpotter@hogwarts.edu',
      'name' => 'hpotter',
      'init' => 'hpotter@hogwarts.edu',
      'status' => 1,
      'signature' => '',
      'data' =>
        array(
          'ldap_authentication' =>
          array(
            'init' =>
            array(
              'sid' => 'activedirectory1',
              'dn' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
              'mail' => 'hpotter@hogwarts.edu',
            ),
          ),
        ),
      'ldap_user_puid' =>
        array(
          'und' =>
          array(
            0 =>
            array(
              'value' => '101',
            ),
          ),
        ),
      'ldap_user_puid_property' =>
        array(
          'und' =>
          array(
            0 =>
            array(
              'value' => 'guid',
            ),
          ),
        ),
      'ldap_user_puid_sid' =>
        array(
          'und' =>
          array(
            0 =>
            array(
              'value' => 'activedirectory1',
            ),
          ),
        ),
      'ldap_user_current_dn' =>
        array(
          'und' =>
          array(
            0 =>
            array(
              'value' => 'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
            ),
          ),
        ),
    );
    $array_diff = array_diff($user_edit, $desired_result);
    // @todo need better diff, this will give false positives in most cases
    //   debug('user_edit,desired_result,diff'); debug( array($user_edit, $desired_result, $array_diff));
    $this->assertTrue(count($array_diff) == 0, t('ldapUserConf::entryToUserEdit retrieved correct property, field, and data values.'), $this->testId('ldapUserConf::entryToUserEdit'));
    if (count($array_diff) != 0) {
      debug('ldapUserConf::entryToUserEdit failed.  resulting user edit array:'); debug($user_edit); debug('desired result:'); debug($desired_result); debug('array_diff:'); debug($array_diff);
    }

    $is_synched_tests = array(
      LDAP_USER_EVENT_CREATE_DRUPAL_USER => array(
        0 => array('[property.fake]', '[property.data]', '[property.uid]'),
        1 => array('[property.mail]', '[property.name]', '[field.ldap_user_puid]', '[field.ldap_user_puid_property]', '[field.ldap_user_puid_sid]', '[field.ldap_user_current_dn]'),
      ),
      LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER => array(
        0 => array('[property.fake]', '[property.data]', '[property.uid]', '[field.ldap_user_puid]', '[field.ldap_user_puid_property]', '[field.ldap_user_puid_sid]'),
        1 => array('[property.mail]', '[property.name]', '[field.ldap_user_current_dn]'),
      ),
    );

    $debug = array();
    $fail = FALSE;
    foreach ($is_synched_tests as $prov_event => $tests) {
      foreach ($tests as $boolean_result => $attribute_tokens) {
        foreach ($attribute_tokens as $attribute_token) {
          $is_synched = $ldap_user_conf->isSynched($attribute_token, array($prov_event), LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER);
          // debug("is_synched_tests: is_synched=$is_synched, attribute_token=$attribute_token, prov_event=$prov_event");.
          if ((int) $is_synched !== (int) $boolean_result) {
            $fail = TRUE;
            $debug[$attribute_token] = "isSynched($attribute_token, array($prov_event),
              LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER) returned $is_synched when it should have returned " . (int) $boolean_result;
          }
        }
      }
    }

    $this->assertFalse($fail, t('ldapUserConf::isSynched works'), $this->testId('ldapUserConf::isSynched'));
    if ($fail) {
      debug('ldapUserConf::isSynched failures:'); debug($debug);
    }

    $this->assertTrue($ldap_user_conf->isDrupalAcctProvisionServer('activedirectory1'), t('isDrupalAcctProvisionServer works'), $this->testId('isDrupalAcctProvisionServer'));
    $this->assertFalse($ldap_user_conf->isLdapEntryProvisionServer('activedirectory1'), t('isLdapEntryProvisionServer works'), $this->testId('isLdapEntryProvisionServer'));

    $ldap_user_required_attributes = $ldap_user_conf->getLdapUserRequiredAttributes(LDAP_USER_PROV_DIRECTION_ALL);

    $provision_enabled_truth = (boolean) (
      $ldap_user_conf->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, LDAP_USER_DRUPAL_USER_PROV_ON_USER_UPDATE_CREATE)
      && $ldap_user_conf->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, LDAP_USER_DRUPAL_USER_PROV_ON_AUTHENTICATE)
      && !$ldap_user_conf->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY, LDAP_USER_LDAP_ENTRY_PROV_ON_USER_UPDATE_CREATE)
    );
    $this->assertTrue($provision_enabled_truth, t('provisionEnabled works'), $this->testId('provisionEnabled.1'));

    $provision_enabled_false =
    ($ldap_user_conf->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY, LDAP_USER_DRUPAL_USER_PROV_ON_USER_UPDATE_CREATE) ||
    $ldap_user_conf->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY, LDAP_USER_DRUPAL_USER_PROV_ON_AUTHENTICATE)  ||
    $ldap_user_conf->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, LDAP_USER_LDAP_ENTRY_PROV_ON_USER_UPDATE_CREATE));
    $this->assertFalse($provision_enabled_false, t('provisionEnabled works'), $this->testId('provisionEnabled.2'));

    $account = new stdClass();
    $account->name = 'hpotter';
    $params = array('ldap_context' => 'ldap_user_prov_to_drupal', 'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER);
    list($ldap_entry, $error) = $ldap_user_conf->drupalUserToLdapEntry($account, 'activedirectory1', $params);
    // debug('ldap_entry'); debug($ldap_entry);
    $account = NULL;
    $user_edit = array('name' => 'hpotter');

    // Test method provisionDrupalAccount()
    $hpotter = $ldap_user_conf->provisionDrupalAccount($account, $user_edit, NULL, TRUE);

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
    // Test account exists with correct username, mail, fname, puid, puidfield, dn
    // Change some user mock ldap data first, (mail and fname) then synch.
    $account = user_load_by_name('hpotter');

    $user_edit = NULL;
    $ldap_user_conf->ldapUserSynchMappings = array();
    $sid = 'activedirectory1';
    $ldap_user_conf->ldapUserSynchMappings[LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER]['[property.mail]'] = array(
      'sid' => $sid,
      'ldap_attr' => '[mail]',
      'user_attr' => '[property.mail]',
      'convert' => 0,
      'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
      'ldap_contexts' => array('ldap_user_insert_drupal_user', 'ldap_user_update_drupal_user', 'ldap_authentication_authenticate'),
      'prov_events' => array(LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER),
      'name' => 'Property: Mail',
      'enabled' => TRUE,
      'config_module' => 'ldap_servers',
      'prov_module' => 'ldap_user',
      'user_tokens' => '',
    );
    $ldap_user_conf->save();

    $this->testFunctions->setFakeServerUserAttribute($sid, 'cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'mail', 'hpotter@owlcarriers.com', 0);
    // Clear server cache;.
    $ldap_server = ldap_servers_get_servers('activedirectory1', NULL, TRUE, TRUE);
    $user = $ldap_user_conf->synchToDrupalAccount($account, $user_edit, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER, NULL, TRUE);

    $hpotter = user_load_by_name('hpotter');
    $hpotter_uid = $hpotter->uid;
    $success = ($hpotter->mail == 'hpotter@owlcarriers.com');

    $this->assertTrue($success, t('synchToDrupalAccount worked for property (mail) for hpotter'), $this->testId());
    if (!$success) {
      debug("hpotter mail after synchToDrupalAccount :" . $hpotter->mail);
      $ldap_server = ldap_servers_get_servers($sid, NULL, TRUE, TRUE);
      debug('ldap_server'); debug($ldap_server);
    }

    /**
     * test for username change and provisioning with puid conflict
     * hpotter drupal user already exists and has correct puid
     * change samaccountname value (puid field) of hpotter ldap entry and attempt to provision account with new username (hpotterbrawn)
     * return should be old drupal account (same uid)
     */

    $this->testFunctions->setFakeServerUserAttribute('activedirectory1', 'cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'samaccountname', 'hpotter-granger', 0);
    $account = NULL;
    $user_edit = array('name' => 'hpotter-granger');
    $hpottergranger = $ldap_user_conf->provisionDrupalAccount($account, $user_edit, NULL, TRUE);

    $this->testFunctions->setFakeServerUserAttribute('activedirectory1', 'cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'samaccountname', 'hpotter', 0);
    $pass = (is_object($hpottergranger) && is_object($hpotter) && $hpotter->uid == $hpottergranger->uid);
    $this->assertTrue($pass, t('provisionDrupalAccount recognized PUID conflict and synched instead of creating a conflicted drupal account.'), $this->testId('provisionDrupalAccount function test with existing user with same puid'));
    if (!$pass) {
      debug('hpotter'); debug($hpotter); debug('hpottergranger'); debug($hpottergranger);
    }
    $authmaps = user_get_authmaps('hpotter-granger');
    $pass = $authmaps['ldap_user'] == 'hpotter-granger';
    $this->assertTrue($pass, t('provisionDrupalAccount recognized PUID conflict and fixed authmap.'), $this->testId());

    $pass = is_object($hpottergranger) && $hpottergranger->name == 'hpotter-granger';
    $this->assertTrue($pass, t('provisionDrupalAccount recognized PUID conflict and fixed username.'), $this->testId());

    $user_edit = array('name' => 'hpotter');
    // @FIXME
    // user_save() is now a method of the user entity.
    // $hpotter = user_save($hpottergranger, $user_edit, 'ldap_user');
    // Delete and recreate test account to make sure account is in correct state
    $ldap_user_conf->deleteDrupalAccount('hpotter');
    // @FIXME
    $this->assertFalse(
    // To reset the user cache, use EntityStorageInterface::resetCache().
    \Drupal::entityManager()->getStorage('user')->load($hpotter_uid), t('deleteDrupalAccount deleted hpotter successfully'), $this->testId());

    $ldap_server = ldap_servers_get_servers('activedirectory1', 'enabled', TRUE, TRUE);
    $ldap_server->refreshFakeData();
    $account = NULL;
    $user_edit = array('name' => 'hpotter');
    $hpotter = $ldap_user_conf->provisionDrupalAccount($account, $user_edit, NULL, TRUE);

  }

  /**
   *
   */
  function testProvisionToDrupal() {
    // @FIXME
    /* @FIXME
    // // This looks like another module's variable. You'll need to rewrite this call
    // // to ensure that it uses the correct configuration object.
    // /**
    //      * test that $ldap_user_conf->synchToDrupalAccount() works for various contexts.
    //      * make sure changing when a given field/property is flagged for a particular context, everything works
    //      * tests one property (property.mail) and one field (field.field_lname) as well as username, puid
    //      */
    //
    /*       // just to give warning if setup doesn't succeed.  may want to take these out at some point.
    //     $setup_success = (
    //         module_exists('ldap_user') &&
    //         module_exists('ldap_servers') &&
    //         (variable_get('ldap_simpletest', 0) > 0)
    );

    $this->assertTrue($setup_success, ' ldap_user setup successful', $this->testId("setup"));
     */

    $sid = 'activedirectory1';
    $sids = array($sid);
    $this->prepTestData('hogwarts', $sids, 'provisionToDrupal', 'default');
    $tests = array();

    $tests[] = array(
      'disabled' => 0,
      'user' => 'hpotter',
      'field_name' => 'field_lname',
      'field_values' => array(array('sn' => 'Potter'), array('sn' => 'Pottery-Chard')),
    // First value is what is desired on synch, second if no sycn.
      'field_results' => array('Potter', 'Pottery-Chard'),
      'mapping' => array(
        'sid' => $sid,
        'name' => 'Field: Last Name',
        'ldap_attr' => '[SN]',
        'user_attr' => '[field.field_lname]',
        'convert' => 0,
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
        'prov_events' => array(LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER),
        'user_tokens' => '',
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'enabled' => TRUE,
      ),
    );

    // Test for compound tokens.
    $tests[] = array(
      'disabled' => 0,
      'user' => 'hpotter',
      'field_name' => 'field_display_name',
      'field_values' => array(array('givenname' => 'Harry', 'sn' => 'Potter'), array('givenname' => 'Sir Harry', 'sn' => 'Potter')),
    // Desired results.
      'field_results' => array('Harry Potter', 'Sir Harry Potter'),
      'mapping' => array(
        'sid' => $sid,
        'ldap_attr' => '[givenName] [sn]',
        'user_attr' => '[field.field_display_name]',
        'convert' => 0,
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
        'prov_events' => array(LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER),
        'name' => 'Field: Display Name',
        'enabled' => TRUE,
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ),
    );

    // Test for constants in use (e.g. "Smith" and "0") instead of tokens e.g. "[sn]" and "[enabled]".
    $tests[] = array(
      'disabled' => 0,
      'user' => 'hpotter',
      'field_name' => 'field_lname',
      'field_values' => array(array('sn' => 'Potter1'), array('sn' => 'Potter2')),
      'field_results' => array('Smith', 'Smith'),
      'mapping' => array(
        'sid' => $sid,
        'name' => 'Field: Last Name',
    // Testing of a constant mapped to a field.  that is everyone should have last name smith.
        'ldap_attr' => 'Smith',
        'user_attr' => '[field.field_lname]',
        'convert' => 0,
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
        'prov_events' => array(LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER),
        'user_tokens' => '',
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'enabled' => TRUE,

      ),
    );

    // Test for compound tokens.
    $tests[] = array(
      'disabled' => 0,
      'user' => 'hpotter',
      'property_name' => 'signature',
      'property_values' => array(array('cn' => 'hpotter'), array('cn' => 'hpotter2')),
      'property_results' => array('hpotter@hogwarts.edu', 'hpotter2@hogwarts.edu'),
      'mapping' => array(
        'sid' => $sid,
        'ldap_attr' => '[cn]@hogwarts.edu',
        'user_attr' => '[property.signature]',
        'convert' => 0,
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
        'prov_events' => array(LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER),
        'name' => 'Property: Signature',
        'enabled' => TRUE,
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ),
    );

    $tests[] = array(
      'disabled' => 0,
      'user' => 'hpotter',
      'property_name' => 'mail',
      'property_values' => array(array('mail' => 'hpotter@hogwarts.edu'), array('mail' => 'hpotter@owlmail.com')),
      'property_results' => array('hpotter@hogwarts.edu', 'hpotter@owlmail.com'),
      'mapping' => array(
        'sid' => $sid,
        'ldap_attr' => '[mail]',
        'user_attr' => '[property.mail]',
        'convert' => 0,
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
        'prov_events' => array(LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER),
        'name' => 'Property: Mail',
        'enabled' => TRUE,
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ),
    );

    $tests[] = array(
      'disabled' => 0,
      'user' => 'hpotter',
      'property_name' => 'status',
      'property_values' => array(array(0 => 'z'), array(0 => 'z')),
      'property_results' => array(0, 0),
      'mapping' => array(
        'sid' => $sid,
        'ldap_attr' => '0',
    // Testing of a constant mapped to property.
        'user_attr' => '[property.status]',
        'convert' => 0,
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
        'prov_events' => array(LDAP_USER_EVENT_CREATE_DRUPAL_USER),
        'name' => 'Property: Status',
        'enabled' => TRUE,
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
        'user_tokens' => '',
      ),
    );

    // @todo test with binary field
    // @todo case sensitivity in tokens and user_attr in mappings

    $test_prov_events = array(
      LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER => array(
        LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER,
        LDAP_USER_EVENT_CREATE_DRUPAL_USER,
      ),

      LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY => array(
        LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY,
        LDAP_USER_EVENT_CREATE_LDAP_ENTRY,
      ),
    );

    $this->privileged_user = $this->drupalCreateUser(array(
      'administer site configuration',
      'administer users',
    ));

    /** Tests for various synch contexts **/
    foreach ($tests as $j => $test) {

      $field_name = isset($test['field_name']) ? $test['field_name'] : FALSE;
      $property_name = isset($test['property_name']) ? $test['property_name'] : FALSE;
      $direction = ($property_name) ? $test['mapping']['direction'] : $test['mapping']['direction'];
      // Test for each provision event.
      foreach ($test_prov_events[$direction] as $i => $prov_event) {

        // 1. set fake ldap values for field and property in fake ldap server
        // and clear out mappings and set to provision account with test field and prop[0] on provision.
        $ldap_server = ldap_servers_get_servers('activedirectory1', 'enabled', TRUE);
        $this->prepTestData('hogwarts', $sids, 'provisionToDrupal', 'default');
        $ldap_user_conf = ldap_user_conf('admin', TRUE);
        if ($property_name) {
          $token_attributes = array();
          ldap_servers_token_extract_attributes($token_attributes, $test['mapping']['ldap_attr']);
          foreach ($token_attributes as $attr_name => $attr_parts) {
            $this->testFunctions->setFakeServerUserAttribute(
              'activedirectory1',
              'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
              $attr_name,
              $test['property_values'][0][$attr_name],
              0);
          }
          $property_token = '[property.' . $property_name . ']';
          $ldap_user_conf->ldapUserSynchMappings[$direction][$property_token] = $test['mapping'];
        }
        if ($field_name) {
          $token_attributes = array();
          ldap_servers_token_extract_attributes($token_attributes, $test['mapping']['ldap_attr']);
          // debug('token_attributes'); debug($token_attributes);
          foreach ($token_attributes as $attr_name => $attr_parts) {
            $this->testFunctions->setFakeServerUserAttribute(
              'activedirectory1',
              'cn=hpotter,ou=people,dc=hogwarts,dc=edu',
              $attr_name,
              $test['field_values'][0][Unicode::strtolower($attr_name)],
              0);
          }
          $field_token = '[field.' . $field_name . ']';
          $ldap_user_conf->ldapUserSynchMappings[$direction][$field_token] = $test['mapping'];
        }

        $ldap_user_conf->save();
        $ldap_user_conf = ldap_user_conf('admin', TRUE);
        // debug("ldap_user_conf in prep field_token=$field_token"); debug($ldap_user_conf->synchMapping); debug($ldap_user_conf->ldapUserSynchMappings);.
        ldap_user_ldap_provision_semaphore(NULL, NULL, NULL, TRUE);
        ldap_servers_flush_server_cache();

        // 2. delete user.
        $username = $test['user'];
        $user_object = user_load_by_name($username);
        if (is_object($user_object)) {
          // Watch out for this.
          $user_object->uid->delete();
        }

        // 3. create new user with provisionDrupalAccount.
        $account = NULL;
        $user_edit = array('name' => $username);
        // $this->ldapTestId = $this->module_name . ': provisionDrupalAccount function test';.
        $result = $ldap_user_conf->provisionDrupalAccount($account, $user_edit, NULL, TRUE);
        list($user_object, $user_entity) = ldap_user_load_user_acct_and_entity($username);
        if ($property_name) {
          // If intended to synch.
          if (in_array($prov_event, $ldap_user_conf->ldapUserSynchMappings[$direction][$property_token]['prov_events'])) {
            $property_success = ($user_object->{$property_name} == $test['property_results'][0]);
            $this->assertTrue($property_success, t("provisionDrupalAccount worked for property $property_name"), $this->testId(":provisionDrupalAccount.i=$j.prov_event=$prov_event"));
            if (!$property_success) {
              // debug($user_entity);
              debug('field fail,' . $property_name); debug($user_entity->{$property_name}); debug($test['property_results'][0]);
            }
          }
          else {
            // debug("property_name=$property_name not configured to provisionDrupalAccount on drupal user create for direction=$direction and prov_event=$prov_event");.
          }
        }
        if ($field_name) {
          // debug("property_name=$property_name, prov_event=$prov_event, direction=$direction, field_token=$field_token, sid=$sid, ldap_user_conf->ldapUserSynchMappings $direction - $sid"); debug($ldap_user_conf->ldapUserSynchMappings[$direction][$sid]);.
          // If intended to synch.
          if (in_array($prov_event, $ldap_user_conf->ldapUserSynchMappings[$direction][$field_token]['prov_events'])) {
            $field_success = isset($user_entity->{$field_name}['und'][0]['value']) &&
              $user_entity->{$field_name}['und'][0]['value'] == $test['field_results'][0];
            $this->assertTrue($field_success, t("provisionDrupalAccount worked for field $field_name"), $this->testId(":provisionDrupalAccount.i=$j.prov_event=$prov_event"));
            if (!$field_success) {
              // debug($user_entity);
              debug('field fail,' . $field_name); debug($user_entity->{$field_name}); debug($test['field_results'][0]);
            }
          }
          else {
            debug("field_name=$field_name not configured to provisionDrupalAccount on drupal user create for direction=$direction and prov_event=$prov_event");
          }
        }
        ldap_user_ldap_provision_semaphore(NULL, NULL, NULL, TRUE);
      }

      /**
        * manually create drupal user with option of not ldap associated checked
        */

      if ($hpotter = user_load_by_name('hpotter')) {
        $hpotter->uid->delete();
      }
      $this->assertFalse(user_load_by_name('hpotter'), t('hpotter removed before manual account creation test'), $this->testId('manual non ldap account created'));

      $this->drupalLogout();
      $this->drupalLogin($this->privileged_user);
      $this->drupalGet('admin/people/create');
      $edit = array(
        'name' => 'hpotter',
        'mail' => 'hpotter@hogwarts.edu',
        'pass[pass1]' => 'goodpwd',
        'pass[pass2]' => 'goodpwd',
        'notify' => FALSE,
        'ldap_user_association' => LDAP_USER_MANUAL_ACCT_CONFLICT_NO_LDAP_ASSOCIATE,
      );
      $this->drupalPost('admin/people/create', $edit, t('Create new account'));

      $hpotter = user_load_by_name('hpotter');
      $this->assertTrue($hpotter, t('hpotter created via ui form'), $this->testId('manual non ldap account created'));
      $this->assertTrue($hpotter && !ldap_user_is_ldap_associated($hpotter), t('hpotter not ldap associated'), $this->testId('manual non ldap account created'));

    }
    /**
     * $entry = $servers['activedirectory1']->dnExists($desired_dn, 'ldap_entry');
          *      * $this->assertFalse($entry, t("Corresponding LDAP entry deleted when Drupal Account deleted for " . $username), $this->ldapTestId);
     */
  }

}
