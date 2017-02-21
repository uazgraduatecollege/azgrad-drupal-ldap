<?php

namespace Drupal\ldap_servers\Form;

use Drupal\Component\Utility\Unicode;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Entity\EntityForm;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Helper\LdapConfiguration;

/**
 * Use Drupal\Core\Form\FormBase;.
 */
class ServerTestForm extends EntityForm {

  /** @var Server $ldapServer */
  protected $ldapServer;

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_servers_test_form';
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state, $ldap_server = NULL) {
    if ($ldap_server) {
      $this->ldapServer = $ldap_server;
    }

    $form['#title'] = t('Test LDAP Server Configuration: @server', array('@server' => $this->ldapServer->label()));

    $form['#prefix'] = t('This form tests an LDAP configuration to see if
    it can bind and basic user and group functions.  It also shows token examples
    and a sample user.  The only data this function will modify is the test LDAP group, which will be deleted and added');

    if (!\Drupal::moduleHandler()->moduleExists('ldap_user')) {
      $form['error'] = [
        '#markup' => '<h3>' . t('This form requires ldap_user to function correctly, please enable it.') . '</h3>',
      ];
      return $form;
    }

    $properties = array();

    $settings = array(
      '#theme' => 'item_list',
      '#items' => $properties,
      '#list_type' => 'ul',
    );
    $form['server_variables'] = array(
      '#markup' => drupal_render($settings),
    );

    $form['id'] = [
      '#type' => 'hidden',
      '#title' => t('Machine name for this server'),
      '#default_value' => $this->ldapServer->id(),
    ];

    $form['binding']['bindpw'] = [
      '#type' => 'password',
      '#title' => t('Password for non-anonymous search'),
      '#size' => 20,
      '#maxlength' => 255,
      '#description' => t('Leave empty to test with currently stored password.'),
    ];

    $form['testing_drupal_username'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Drupal Username'),
      '#default_value' => $this->ldapServer->get('testing_drupal_username'),
      '#size' => 30,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s configuration against an actual username.  The user need not exist in Drupal and testing will not affect the user\'s LDAP or Drupal Account.'),
    ];

    $form['testing_drupal_user_dn'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Drupal DN'),
      '#default_value' => $this->ldapServer->get('testing_drupal_user_dn'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s configuration against an actual username.  The user need not exist in Drupal and testing will not affect the user\'s LDAP or Drupal Account.'),
    ];

    $form['grp_test_grp_dn'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Group DN'),
      '#default_value' => $this->ldapServer->get('grp_test_grp_dn'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s group configuration.'),
    ];

    $form['grp_test_grp_dn_writeable'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Group DN that is writeable. Warning!  In test, this group will be deleted, created, have members added to it!'),
      '#default_value' => $this->ldapServer->get('grp_test_grp_dn_writeable'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s group configuration.'),
    ];

    if ($this->ldapServer->get('bind_method') == Server::$bindMethodAnonUser) {
      $form['testing_drupal_userpw'] = [
        '#type' => 'password',
        '#title' => t('Testing Drupal User Password'),
        '#size' => 30,
        '#maxlength' => 255,
        '#description' => t('This is optional and used for testing this server\'s configuration against the username above.'),
      ];
    }

    $form['submit'] = [
      '#type' => 'submit',
      '#value' => 'Test',
      '#weight' => 100,
    ];

    if ($form_state->get(['ldap_server_test_data'])) {
      $test_data = $form_state->get(['ldap_server_test_data']);

      if (isset($test_data['username']) && isset($test_data['ldap_user'])) {
        // This used to be done by theme_ldap_server_ldap_entry_table.
        $header = array('Attribute Name', 'Instance', 'Value', 'Token');
        $rows = array();
        foreach ($test_data['ldap_user']['attr'] as $key => $value) {
          if (is_numeric($key) || $key == 'count') {
          }
          elseif (count($value) > 1) {
            $count = (int) $value['count'];
            foreach ($value as $i => $value2) {

              if ((string) $i == 'count') {
                continue;
              }
              elseif ($i == 0 && $count == 1) {
                $token = TokenProcessor::$token_pre . $key . TokenProcessor::$token_post;
              }
              elseif ($i == 0 && $count > 1) {
                $token = TokenProcessor::$token_pre . $key . TokenProcessor::$token_del . '0' . TokenProcessor::$token_post;
              }
              elseif (($i == $count - 1) && $count > 1) {
                $token = TokenProcessor::$token_pre . $key . TokenProcessor::$token_del . 'last' . TokenProcessor::$token_post;
              }
              elseif ($count > 1) {
                $token = TokenProcessor::$token_pre . $key . TokenProcessor::$token_del . $i . TokenProcessor::$token_post;
              }
              else {
                $token = "";
              }
              $rows[] = array('data' => array($key, $i, self::binaryCheck($value2), $token));
            }
          }
        }

        $settings = array(
          '#theme' => 'table',
          '#header' => $header,
          '#rows' => $rows,
        );

        $form['#suffix'] = '<div class="content">
        <h2>' . t('LDAP Entry for %username (dn: %dn)', array('%dn' => $test_data['ldap_user']['dn'], '%username' => $test_data['username'])) . '</h2>'
          . drupal_render($settings) . '</div>';
      }

      $titles = [
        'basic' => 'Test Results',
        'group1' => 'Group Create, Delete, Add Member, Remove Member Tests',
        'group2' => 'User Group Membership Functions Test',
        'tokens' => 'User Token Samples',
        'groupfromDN' => 'Groups Derived From User DN',
      ];

      foreach ($test_data['results_tables'] as $table_name => $table_data) {
        $settings = array(
          '#theme' => 'table',
          '#header' => array('Test', 'Result'),
          '#rows' => $table_data,
        );
        $form['#suffix'] .= '<h2>' . $titles[$table_name] . '</h2>' . drupal_render($settings);
      }

      if (function_exists('dpm') && !empty($test_data['username'])) {
        $user_name = $test_data['username'];
        if ($user = user_load_by_name($user_name)) {
          dpm("Corresponding Drupal user object for: $user_name");
          dpm($user);
          if (function_exists('entity_load_single')) {
            $user_entity = entity_load_single('user', $user->uid);
            dpm("Drupal user entity for: $user_name");
            dpm($user_entity);
          }
          dpm("Test Group LDAP Entry");
          // @FIXME: group_entry is undefined.
          dpm($test_data['group_entry'][0]);
        }
      }
    }
    return $form;
  }

  /**
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $server = Server::load($values['id']);

    if (!$values['id']) {
      $form_state->setErrorByName(NULL, t('No server id found in form'));
    }
    elseif (!$server) {
      $form_state->setErrorByName(NULL, t('Failed to create server object for server with server id=%id', [
        '%id' => $values['id'],
      ]));
    }
  }

  /**
   *
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    // Pass data back to form builder.
    $form_state->setRebuild(TRUE);

    $errors = FALSE;
    $has_errors = FALSE;
    $values = $form_state->getValues();
    $id = $values['id'];
    $this->ldapServer = Server::load($id);

    // $result = t('<h1>Test of name </h2>',$server_conf);.
    $results = [];
    $results_tables = [];
    if ($values['bindpw']) {
      $bindpw = $values['bindpw'];
      $bindpw_type = t('entered in form.');
    }
    else {
      $bindpw = NULL;
      $bindpw_type = t('stored in configuration');
    }

    if ($this->ldapServer->get('bind_method') == Server::$bindMethodServiceAccount) {
      $results_tables['basic'][] = [
        t('Binding with DN for non-anonymous search (%bind_dn).  Using password ', [
          '%bind_dn' => $this->ldapServer->get('binddn'),
        ]) . ' ' . $bindpw_type . '.',
        '',
      ];
    }
    else {
      $results_tables['basic'][] = [
        t('Binding with null DN for anonymous search.'),
        '',
      ];
    }

    if (@$values['grp_test_grp_dn_writeable'] && @$values['grp_test_grp_dn']) {
      $user_test_dn = @$values['grp_test_grp_dn'];
      $group_create_test_dn = $values['grp_test_grp_dn_writeable'];
      $group_create_test_attr = [
        'objectClass' => [
          $this->ldapServer->get('grp_object_cat'),
          'top',
        ],
      ];

      // 1. delete test group if it exists.
      if ($this->ldapServer->dnExists($group_create_test_dn, 'ldap_entry', [
        'cn',
        'member',
      ])
      ) {
        $result = $this->ldapServer->groupRemoveGroup($group_create_test_dn, FALSE);
      }

      $group_exists = $this->ldapServer->dnExists($group_create_test_dn, 'ldap_entry', [
        'cn',
        'member',
      ]);
      $result = ($group_exists === FALSE) ? "PASS" : "FAIL";
      $results_tables['group1'][] = [
        "Starting test without group: $group_create_test_dn ",
        $result,
      ];

      // 2. make sure call to members in empty group returns false.
      $result = $this->ldapServer->groupAllMembers($group_create_test_dn);
      $result = ($result === FALSE) ? "PASS" : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupAllMembers($group_create_test_dn) call on nonexistent group returns FALSE",
        $result,
      ];

      // 3. add group.
      $result = $this->ldapServer->groupAddGroup($group_create_test_dn, $group_create_test_attr);
      $result = ($result) ? "PASS" : 'FAIL';
      $attr = serialize($group_create_test_attr);
      $results_tables['group1'][] = [
        "LdapServer::groupAddGroup($group_create_test_dn, $attr)",
        $result,
      ];

      // 4. call to all members in an empty group returns emtpy array, not FALSE.
      $result = $this->ldapServer->groupAllMembers($group_create_test_dn);
      $result = (is_array($result) && count($result) == 0) ? 'PASS' : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupAllMembers($group_create_test_dn) returns empty array for empty group ",
        $result,
      ];

      // 5. add member to group.
      $result = $this->ldapServer->groupAddMember($group_create_test_dn, $user_test_dn);
      $result = is_array($this->ldapServer->groupAllMembers($group_create_test_dn)) ? 'PASS' : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupAddMember($group_create_test_dn, $user_test_dn)",
        $result,
      ];

      // 6. try to remove group with member in it.
      $only_if_group_empty = TRUE;
      $result = $this->ldapServer->groupRemoveGroup($group_create_test_dn, $only_if_group_empty);
      $result = ($result) ? 'FAIL' : 'PASS';
      $results_tables['group1'][] = [
        "LdapServer::groupRemoveGroup($group_create_test_dn, $only_if_group_empty)",
        $result,
      ];

      // 7. remove group member.
      $result = $this->ldapServer->groupRemoveMember($group_create_test_dn, $user_test_dn);
      $result = $this->ldapServer->groupAllMembers($group_create_test_dn);
      $result = (is_array($result) && count($result) == 0) ? 'PASS' : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupRemoveMember($group_create_test_dn, $user_test_dn)",
        $result,
      ];

      $only_if_group_empty = TRUE;
      $result = $this->ldapServer->groupRemoveGroup($group_create_test_dn, $only_if_group_empty);
      $result = ($this->ldapServer->dnExists($group_create_test_dn, 'ldap_entry', [
        'cn',
        'member',
      ])) ? "FAIL" : 'PASS';
      $results_tables['group1'][] = [
        "LdapServer::groupRemoveGroup($group_create_test_dn, $only_if_group_empty)",
        $result,
      ];
    }

    // Connect to ldap.
    // @FIXME: testBindingCredentials call function bind and throw an error (no error log)
    list($has_errors, $more_results) = $this->ldapServer->testBindingCredentials($bindpw, $results_tables);

    $results = array_merge($results, $more_results);

    if ($this->ldapServer->get('bind_method') == Server::$bindMethodAnonUser) {
      drupal_set_message('Bind method anonymous, user.');
      list($has_errors, $more_results, $ldap_user) = $this->ldapServer->testUserMapping($values['testing_drupal_username']);
      $results = array_merge($results, $more_results);
      if (!$has_errors) {
        $mapping[] = "dn = " . $ldap_user['dn'];
        foreach ($ldap_user['attr'] as $key => $value) {
          if (is_array($value)) {
            $mapping[] = "$key = " . $value[0];
          }
        }

        $item_list = array(
          '#list_type' => 'ul',
          '#theme' => 'item_list',
          '#items' => $mapping,
          '#title' => t('Attributes available to anonymous search', [
            '%bind_dn' => $this->ldapServer->get('binddn'),
          ]),
        );
        $results_tables['basic'][] = [
          render($item_list),
        ];
      }
      $results_tables['basic'][] = [
        t('Binding with DN (%bind_dn).  Using supplied password ', [
          '%bind_dn' => $ldap_user['dn'],
        ]),
      ];
      $result = $this->ldapServer->bind($ldap_user['dn'], $values['testing_drupal_userpw'], FALSE);
      if ($result == Server::LDAP_SUCCESS) {
        $results_tables['basic'][] = [
          t('Successfully bound to server'),
          t('PASS'),
        ];
      }
      else {
        $results_tables['basic'][] = [
          t('Failed to bind to server. ldap error #') . $result . ' ' . $this->ldapServer->errorMsg('ldap'),
          t('FAIL'),
        ];
      }
    }

    if (!$has_errors && isset($values['grp_test_grp_dn'])) {
      list($group_entry, $values, $results_tables) = $this->testGroupDN($values, $results_tables);
    }

    list($has_errors, $more_results, $ldap_user) = $this->ldapServer->testUserMapping($values['testing_drupal_username']);
    $tokenHelper = new TokenProcessor();
    $tokens = ($ldap_user && isset($ldap_user['attr'])) ? $tokenHelper->tokenizeEntry($ldap_user['attr'], 'all', TokenProcessor::$token_pre, TokenProcessor::$token_post) : [];
    foreach ($tokens as $key => $value) {
      $results_tables['tokens'][] = [$key, $this->binaryCheck($value)];
    }
    $form_state->set(['ldap_server_test_data'], [
      'username' => $values['testing_drupal_username'],
      'results_tables' => $results_tables,
    ]);

    if (isset($ldap_user)) {
      $form_state->set(['ldap_server_test_data', 'ldap_user'], $ldap_user);
    }

    if (isset($group_entry)) {
      $form_state->set(['ldap_server_test_data', 'group_entry'], $group_entry);
    }

  }

  /**
   * @param $values
   * @param $results_tables
   * @return array
   */
  private function testGroupDN($values, $results_tables) {
    $group_dn = $values['grp_test_grp_dn'];
    $group_entry = $this->ldapServer->search($group_dn, 'objectClass=*');
    $user = isset($values['testing_drupal_username']) ? $values['testing_drupal_username'] : NULL;

    foreach ([FALSE, TRUE] as $nested) {
      // FALSE.
      $nested_display = ($nested) ? 'Yes' : 'No';
      if ($user) {
        // This is the parent function that will call FromUserAttr or FromEntry.
        $memberships = $this->ldapServer->groupMembershipsFromUser($user, 'group_dns', $nested);
        $settings = array(
          '#theme' => 'item_list',
          '#items' => $memberships,
          '#list_type' => 'ul',
        );
        $result = drupal_render($settings);

        $results_tables['group2'][] = [
          'Group memberships from user ("group_dns", nested=' . $nested_display . ') (' . count($memberships) . ' found)',
          $result,
        ];

        $result = ($this->ldapServer->groupIsMember($group_dn, $user, $nested)) ? 'Yes' : 'No';
        $group_results = [];
        $group_results[] = [
          'groupIsMember from group DN ' . $group_dn . 'for ' . $user . ' nested=' . $nested_display . ')',
          $result,
        ];

        if ($this->ldapServer->groupUserMembershipsFromAttributeConfigured()) {
          $groupUserMembershipsFromUserAttributes = $this->ldapServer->groupUserMembershipsFromUserAttr($user, $nested);
          $count = count($groupUserMembershipsFromUserAttributes);
          $settings = array(
            '#theme' => 'item_list',
            '#items' => $groupUserMembershipsFromUserAttributes,
            '#list_type' => 'ul',
          );
          $result = drupal_render($settings);

        }
        else {
          $groupUserMembershipsFromUserAttributes = [];
          $result = "'A user LDAP attribute such as memberOf exists that contains a list of their group' is not configured.";
        }
        $results_tables['group2'][] = [
          'Group memberships from user attribute for ' . $user . ' (nested=' . $nested_display . ') (' . count($groupUserMembershipsFromUserAttributes) . ' found)',
          $result,
        ];

        if ($this->ldapServer->groupGroupEntryMembershipsConfigured()) {
          $groupUserMembershipsFromEntry = $this->ldapServer->groupUserMembershipsFromEntry($user, $nested);
          $settings = array(
            '#theme' => 'item_list',
            '#items' => $groupUserMembershipsFromEntry,
            '#list_type' => 'ul',
          );
          $result = drupal_render($settings);

        }
        else {
          $groupUserMembershipsFromEntry = [];
          $result = "Groups by entry not configured.";
        }
        $results_tables['group2'][] = [
          'Group memberships from entry for ' . $user . ' (nested=' . $nested_display . ') (' . count($groupUserMembershipsFromEntry) . ' found)',
          $result,
        ];

        if (count($groupUserMembershipsFromEntry) && count($groupUserMembershipsFromUserAttributes)) {
          $diff1 = array_diff($groupUserMembershipsFromUserAttributes, $groupUserMembershipsFromEntry);
          $diff2 = array_diff($groupUserMembershipsFromEntry, $groupUserMembershipsFromUserAttributes);
          $settings = array(
            '#theme' => 'item_list',
            '#items' => $diff1,
            '#list_type' => 'ul',
          );
          $result1 = drupal_render($settings);

          $settings = array(
            '#theme' => 'item_list',
            '#items' => $diff2,
            '#list_type' => 'ul',
          );
          $result2 = drupal_render($settings);

          $results_tables['group2'][] = [
            "groupUserMembershipsFromEntry and FromUserAttr Diff)",
            $result1,
          ];
          $results_tables['group2'][] = [
            "FromUserAttr and groupUserMembershipsFromEntry Diff)",
            $result2,
          ];
        }
      }
    }

    if ($groups_from_dn = $this->ldapServer->groupUserMembershipsFromDn($user)) {
      $settings = array(
        '#theme' => 'item_list',
        '#items' => $groups_from_dn,
        '#list_type' => 'ul',
      );
    }
    $result = drupal_render($settings);
    $results_tables['groupfromDN'][] = array("Groups from DN", $result);
    return array($group_entry, $values, $results_tables);
  }

  /**
   *
   */
  public static function binaryCheck($input) {
    if (preg_match('~[^\x20-\x7E\t\r\n]~', $input) > 0) {
      return t('Binary (excerpt): @excerpt', array('@excerpt' => Unicode::truncate($input, 120, FALSE, TRUE)));
    }
    else {
      return $input;
    }
  }

  /** Unported legacy code. */

  /**
   * @FIXME: NOT TESTED
   * add a group entry.
   *
   * @Todo: Move out, only called by ServerTestForm.
   *
   * @param string $group_dn
   *   as ldap dn.
   * @param array $attributes
   *   in key value form
   *    $attributes = array(
   *      "attribute1" = "value",
   *      "attribute2" = array("value1", "value2"),
   *      )
   *
   * @return boolean success
   */
  public function groupAddGroup($group_dn, $attributes = array()) {

    if ($this->ldapServer->dnExists($group_dn, 'boolean')) {
      return FALSE;
    }

    $attributes = array_change_key_case($attributes, CASE_LOWER);
    $objectclass = (empty($attributes['objectclass'])) ? $this->ldapServer->groupObjectClass() : $attributes['objectclass'];
    $attributes['objectclass'] = $objectclass;

    /**
     * 2. give other modules a chance to add or alter attributes
     */
    $context = array(
      'action' => 'add',
      'corresponding_drupal_data' => array($group_dn => $attributes),
      'corresponding_drupal_data_type' => 'group',
    );
    $ldap_entries = array($group_dn => $attributes);
    \Drupal::moduleHandler()->alter('ldap_entry_pre_provision', $ldap_entries, $this, $context);
    $attributes = $ldap_entries[$group_dn];

    /**
     * 4. provision ldap entry
     *   @todo how is error handling done here?
     */
    $ldap_entry_created = $this->ldapServer->createLdapEntry($attributes, $group_dn);

    /**
     * 5. allow other modules to react to provisioned ldap entry
     *   @todo how is error handling done here?
     */
    if ($ldap_entry_created) {
      \Drupal::moduleHandler()->invokeAll('ldap_entry_post_provision', [$ldap_entries, $this, $context]);
      return TRUE;
    }
    else {
      return FALSE;
    }

  }

  /**
   * @TODO: NOT TESTED
   * remove a group entry.
   *
   * @param string $group_dn
   *   as ldap dn.
   * @param bool $only_if_group_empty
   *   TRUE = group should not be removed if not empty
   *   FALSE = groups should be deleted regardless of members.
   *
   * @return bool|void
   */
  public function groupRemoveGroup($group_dn, $only_if_group_empty = TRUE) {

    if ($only_if_group_empty) {
      $members = $this->groupAllMembers($group_dn);
      if (is_array($members) && count($members) > 0) {
        return FALSE;
      }
    }
    // @FIXME: Incorrect parameters
    return $this->delete($group_dn);

  }

  /**
   * @TODO: NOT TESTED
   * add a member to a group.
   *
   * @param string $ldap_user_dn
   *   as ldap dn.
   * @param mixed $user
   *    - drupal user object (stdClass Object)
   *    - ldap entry of user (array) (with top level keys of 'dn', 'mail', 'sid' and 'attr' )
   *    - ldap dn of user (array)
   *    - drupal username of user (string)
   *
   * @return bool
   */
  public function groupAddMember($group_dn, $user) {

    $user_ldap_entry = $this->ldapServer->userUserToExistingLdapEntry($user);
    $result = FALSE;
    if ($user_ldap_entry && $this->ldapServer->groupGroupEntryMembershipsConfigured()) {
      $add = array();
      $add[$this->ldapServer->groupMembershipsAttr()] = $user_ldap_entry['dn'];
      $this->ldapServer->connectAndBindIfNotAlready();
      $result = @ldap_mod_add($this->connection, $group_dn, $add);
    }

    return $result;
  }

  /**
   * @FIXME: NOT TESTED
   * Remove a member from a group.
   *
   * @param string $group_dn
   *   as ldap dn.
   * @param mixed $user
   *    - drupal user object (stdClass Object)
   *    - ldap entry of user (array) (with top level keys of 'dn', 'mail', 'sid' and 'attr' )
   *    - ldap dn of user (array)
   *    - drupal username of user (string)
   *
   * @return bool
   */
  public function groupRemoveMember($group_dn, $user) {

    $user_ldap_entry = $this->ldapServer->userUserToExistingLdapEntry($user);
    $result = FALSE;
    if ($user_ldap_entry && $this->ldapServer->groupGroupEntryMembershipsConfigured()) {
      $del = array();
      $del[$this->ldapServer->groupMembershipsAttr()] = $user_ldap_entry['dn'];
      $this->ldapServer->connectAndBindIfNotAlready();
      $result = @ldap_mod_del($this->connection, $group_dn, $del);
    }
    return $result;
  }

  /**
   * Get all members of a group.
   *
   * Currently only used by ServerTestForm and groupRemoveGroup.
   * @todo: NOT IMPLEMENTED: nested groups
   *
   * @param string $group_dn
   *   as ldap dn.
   *
   * @return bool|array
   *   FALSE on error otherwise array of group members (could be users or groups).
   */
  public function groupAllMembers($group_dn) {

    if (!$this->ldapServer->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }
    $attributes = array($this->ldapServer->groupMembershipsAttr(), 'cn');
    $group_entry = $this->ldapServer->dnExists($group_dn, 'ldap_entry', $attributes);
    if (!$group_entry) {
      return FALSE;
    }
    else {
      // If attributes weren't returned, don't give false  empty group.
      if (empty($group_entry['cn'])) {
        return FALSE;
      }
      if (empty($group_entry[$this->ldapServer->groupMembershipsAttr()])) {
        // If no attribute returned, no members.
        return array();
      }
      $members = $group_entry[$this->ldapServer->groupMembershipsAttr()];
      if (isset($members['count'])) {
        unset($members['count']);
      }
      return $members;
    }

    // FIXME: Unreachable statement.
    $this->ldapServer->groupMembersRecursive($current_group_entries, $all_group_dns, $tested_group_ids, 0, $max_levels, $object_classes);

    return $all_group_dns;

  }

  /**
   * @param $drupal_username
   * @param int $direction
   * @param null $ldap_context
   * @return array
   */
  public function testUserMapping($drupal_username, $direction = NULL, $ldap_context = NULL) {
    if ($direction == NULL) {
      $direction = LdapConfiguration::$provisioningDirectionAll;
      // TODO: Remove unused parameter, if really not needed.
    }
    $ldap_user = $this->ldapServer->userUserNameToExistingLdapEntry($drupal_username, $ldap_context);

    $errors = FALSE;
    if (!$ldap_user) {

      $results[] = t('Failed to find test user %username by searching on  %user_attr = %username.',
          array(
            '%username' => $drupal_username,
            '%user_attr' => self::get('user_attr'),
          )
        )
        . ' ' . t('Error Message:') . ' ' . $this->ldapServer->errorMsg('ldap');
      $errors = TRUE;
    }
    else {
      $results[] = t('Found test user %username by searching on  %user_attr = %username.',
        array('%username' => $drupal_username, '%user_attr' => $this->ldapServer->get('user_attr')));
    }
    return array($errors, $results, $ldap_user);
  }

}
