<?php

namespace Drupal\ldap_servers\tests;

use Drupal\Component\Utility\Unicode;
use Drupal\ldap_servers\TokenFunctions;

/**
 * Tests covering ldap_server module.
 *
 * @group ldap
 */
class ServerUITests extends LdapWebTestBase {

  use TokenFunctions;

  /**
   * {@inheritdoc}
   */
  public static function getInfo() {
    return array(
      'name' => 'LDAP Servers Tests',
      'description' => 'Test ldap servers.  Servers module is primarily a storage
        tool for ldap server configuration, so most of testing is just form and db testing.
        there are some api like functions that are also tested.',
      'group' => 'ldap',
    );
  }

  /**
   * {@inheritdoc}
   */
  public function __construct($test_id = NULL) {
    parent::__construct($test_id);
  }

  protected $ldap_test_data;

  public static $modules = array('ldap_servers');

  /**
   *
   */
  public function testUIForms() {

    return;

    // The tests below are disabled due to significant structural mismatch.
    foreach (array(1) as $ctools_enabled) {
      $this->ldapTestId = "testUIForms.ctools.$ctools_enabled";
      if ($ctools_enabled) {
        module_enable(array('ctools'));
      }
      else {
        // module_disable(array('ctools'));.
      }

      $ldap_simpletest_initial = config('ldap_test.settings')->get('simpletest');
      // Need to be out of fake server mode to test ui.
      variable_del('ldap_simpletest');
      $this->privileged_user = $this->drupalCreateUser(array(
        'administer site configuration',
      ));
      $this->drupalLogin($this->privileged_user);

      $sid = 'server1';
      $server_data = array();
      $server_data[$sid] = array(
        'sid'        => array($sid, $sid),
        'name'       => array("Server $sid", "My Server $sid"),
        'status'     => array(1, 1),
        'ldap_type'  => array('openldap', 'ad'),
        'address'    => array("${sid}.ldap.fake", "${sid}.ldap.fake"),
        'port'       => array(389, 7000),
        'tls'        => array(TRUE, FALSE),
        'bind_method' => array(1, 3),
        'binddn'  => array('cn=service-account,ou=people,dc=hogwarts,dc=edu', ''),
        'bindpw'  => array('sdfsdafsdfasdf', 'sdfsdafsdfasdf'),
        'user_attr' => array('sAMAccountName', 'blah'),
        'account_name_attr' => array('sAMAccountName', 'blah'),
        'mail_attr' => array('mail', ''),
        'mail_template' => array('' , '[email]'),
        'unique_persistent_attr' => array('dn', 'uniqueregistryid'),
        'unique_persistent_attr_binary' => array(1, 1, 1, 1),
        'user_dn_expression' => array('cn=%cn,%basedn', 'cn=%username,%basedn'),

        'testing_drupal_username' => array('hpotter', 'hpotter'),
        'testing_drupal_user_dn' => array('cn=hpotter,ou=people,dc=hogwarts,dc=edu', 'cn=hpotter,ou=people,dc=hogwarts,dc=edu'),

        'grp_unused' => array(FALSE, FALSE),
        'grp_object_cat' => array('group', 'group'),
        'grp_nested' => array(FALSE, FALSE),

        'grp_user_memb_attr_exists' => array(1, 1),
        'grp_user_memb_attr' => array('memberof', 'memberof'),

        'grp_memb_attr' => array('member', 'member'),
        'grp_memb_attr_match_user_attr' => array('dn', 'dn'),

        'grp_derive_from_dn' => array(1, 1),
        'grp_derive_from_dn_attr' => array('ou', 'ou'),

        'grp_test_grp_dn' => array('cn=students,ou=groups,dc=hogwarts,dc=edu', 'cn=students,ou=groups,dc=hogwarts,dc=edu'),
        'grp_test_grp_dn_writeable' => array('cn=students,ou=groups,dc=hogwarts,dc=edu', 'cn=students,ou=groups,dc=hogwarts,dc=edu'),

      );

      $lcase_transformed = array(
        'user_attr',
        'account_name_attr',
        'mail_attr',
        'unique_persistent_attr',
        'grp_user_memb_attr',
        'grp_memb_attr_match_user_attr',
        'grp_derive_from_dn_attr',
      );

      /** add server conf test **/
      $this->drupalGet('admin/config/people/ldap/servers/add');

      $edit = array();
      foreach ($server_data['server1'] as $input_name => $input_values) {
        $edit[$input_name] = $input_values[0];
      }
      $this->drupalPost('admin/config/people/ldap/servers/add', $edit, t('Add'));
      $field_to_prop_map = LdapServer::field_to_properties_map();
      $field_to_prop_map['bindpw'] = 'bindpw';
      $factory = \Drupal::service('ldap.servers');
      $ldap_servers = $factory->getAllServers();
      $this->assertTrue(count(array_keys($ldap_servers)) == 1, 'Add form for ldap server added server.', $this->ldapTestId . ' Add Server');
      $this->assertText('LDAP Server Server server1 added', 'Add form confirmation message', $this->ldapTestId . ' Add Server');
      // Assert one ldap server exists in db table
      // Assert load of server has correct properties for each input.
      $mismatches = $this->compareFormToProperties($ldap_servers['server1'], $server_data['server1'], 0, $field_to_prop_map, $lcase_transformed);
      if (count($mismatches)) {
        debug('mismatches between ldap server properties and form submitted values');
        debug($mismatches);
        debug($ldap_servers);
        debug($server_data['server1']);
      }
      $this->assertTrue(count($mismatches) == 0, 'Add form for ldap server properties match values submitted.', $this->ldapTestId . ' Add Server');

      /** update server conf test **/

      $this->drupalGet('admin/config/people/ldap/servers/edit/server1');

      $edit = array();
      foreach ($server_data['server1'] as $input_name => $input_values) {
        if ($input_values[1] !== NULL) {
          $edit[$input_name] = $input_values[1];
        }
      }

      unset($edit['sid']);
      $this->drupalPost('admin/config/people/ldap/servers/edit/server1', $edit, t('Update'));
      $factory = \Drupal::service('ldap.servers');
      $ldap_servers = $factory->getAllServers();
      $this->assertTrue(count(array_keys($ldap_servers)) == 1, 'Update form for ldap server didnt delete or add another server.', $this->ldapTestId . '.Update Server');
      // Assert confirmation message without error
      // assert one ldap server exists in db table
      // assert load of server has correct properties for each input
      // unset($server_data['server1']['bindpw']);.
      $mismatches = $this->compareFormToProperties($ldap_servers['server1'], $server_data['server1'], 1, $field_to_prop_map, $lcase_transformed);
      if (count($mismatches)) {
        debug('mismatches between ldap server properties and form submitted values'); debug($mismatches);
      }
      $this->assertTrue(count($mismatches) == 0, 'Update form for ldap server properties match values submitted.', $this->ldapTestId . '.Update Server');

      /** delete server conf test **/
      $this->drupalGet('admin/config/people/ldap/servers/delete/server1');
      $this->drupalPost('admin/config/people/ldap/servers/delete/server1', array(), t('Delete'));

      $factory = \Drupal::service('ldap.servers');
      $ldap_servers = $factory->getAllServers();

      $this->assertTrue(count(array_keys($ldap_servers)) == 0, 'Delete form for ldap server deleted server.', $this->ldapTestId . '.Delete Server');

      // @FIXME: variable_set('ldap_simpletest', $ldap_simpletest_initial); // return to fake server mode
    }
  }

  /**
   *
   */
  public function compareFormToProperties($object, $data, $item_id, $map, $lcase_transformed) {

    $mismatches = array();
    foreach ($data as $field_id => $values) {
      $field_id = Unicode::strtolower($field_id);
      if (!isset($map[$field_id])) {
        continue;
      }
      $property = $map[$field_id];
      if (!property_exists($object, $property) && !property_exists($object, Unicode::strtolower($property))) {
        continue;
      }
      $property_value = $object->{$property};

      // For cases where string input is not same as array.
      $field_value = isset($values[$item_id + 2]) ? $values[$item_id + 2] : $values[$item_id];

      if ($field_id == 'bindpw') {
        continue;
      }
      if ($field_id == 'basedn') {
        $pass = count($property_value) == 2;
        if (!$pass) {
          debug($property_value);
        }
      }
      else {
        if (in_array($field_id, $lcase_transformed) && is_scalar($field_value)) {
          $field_value = Unicode::strtolower($field_value);
        }
        $property_value_show = (is_scalar($property_value)) ? $property_value : serialize($property_value);
        $field_value_show = (is_scalar($field_value)) ? $field_value : serialize($field_value);

        if (is_array($property_value) && is_array($field_value)) {
          $pass = count(array_diff($property_value, $field_value)) == 0;
        }
        elseif (is_scalar($property_value) && is_scalar($field_value)) {
          $pass = ($property_value == $field_value);
        }
        else {
          $pass = FALSE;
        }
      }
      if (!$pass) {
        // @FIXME: not instaniated likely
        $mismatches[] = "property $property ($property_value_show) does not match field $field_id value ($field_value_show)";
      }
    }

    return $mismatches;
  }

}
