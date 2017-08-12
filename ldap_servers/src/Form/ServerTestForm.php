<?php

namespace Drupal\ldap_servers\Form;

use Drupal\Component\Utility\Unicode;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Entity\EntityForm;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Processor\TokenProcessor;

/**
 * Use Drupal\Core\Form\FormBase;.
 */
class ServerTestForm extends EntityForm {

  /**
   * The main server to work with.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  protected $ldapServer;

  protected $resultsTables = [];

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_servers_test_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, $ldap_server = NULL) {
    if ($ldap_server) {
      $this->ldapServer = $ldap_server;
    }

    $form['#title'] = $this->t('Test LDAP Server Configuration: @server', ['@server' => $this->ldapServer->label()]);

    $form['#prefix'] = $this->t('This form tests an LDAP configuration to see if
    it can bind and basic user and group functions.  It also shows token examples
    and a sample user.  The only data this function will modify is the test LDAP group, which will be deleted and added');

    if (!\Drupal::moduleHandler()->moduleExists('ldap_user')) {
      $form['error'] = [
        '#markup' => '<h3>' . $this->t('This form requires ldap_user to function correctly, please enable it.') . '</h3>',
      ];
      return $form;
    }

    $properties = [];

    $settings = [
      '#theme' => 'item_list',
      '#items' => $properties,
      '#list_type' => 'ul',
    ];
    $form['server_variables'] = [
      '#markup' => drupal_render($settings),
    ];

    $form['id'] = [
      '#type' => 'hidden',
      '#title' => $this->t('Machine name for this server'),
      '#default_value' => $this->ldapServer->id(),
    ];

    if ($this->ldapServer->get('bind_method') == 'anon_user' || $this->ldapServer->get('bind_method') == 'user') {
      $userCredentialsRequired = TRUE;
    }
    else {
      $userCredentialsRequired = FALSE;
    }

    $form['testing_drupal_username'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Testing Drupal Username'),
      '#default_value' => $this->ldapServer->get('testing_drupal_username'),
      '#size' => 30,
      '#maxlength' => 255,
      '#required' => $userCredentialsRequired,
      '#description' => $this->t("This is normally optional and used for testing this server's configuration against an actual username.<br> The user need not exist in Drupal and testing will not affect the user's LDAP or Drupal account. <br> You need to either supply the username or DN for testing with user binding."),
    ];

    if ($userCredentialsRequired) {
      $form['testing_drupal_userpw'] = [
        '#type' => 'password',
        '#title' => $this->t('Testing Drupal User Password'),
        '#size' => 30,
        '#maxlength' => 255,
        '#required' => TRUE,
        '#description' => $this->t('Credentials required for testing with user binding.'),
      ];
    }

    $form['testing_drupal_user_dn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Testing Drupal DN'),
      '#default_value' => $this->ldapServer->get('testing_drupal_user_dn'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => $this->t("This is optional and used for testing this server's configuration against an actual username.<br> The user need not exist in Drupal and testing will not affect the user's LDAP or Drupal Account."),
    ];

    $form['grp_test_grp_dn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Testing Group DN'),
      '#default_value' => $this->ldapServer->get('grp_test_grp_dn'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => $this->t("This is optional and used for testing this server\'s group configuration."),
    ];

    $form['grp_test_grp_dn_writeable'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Testing Group DN that is writeable.'),
      '#default_value' => $this->ldapServer->get('grp_test_grp_dn_writeable'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => $this->t('<strong>Notice: Functionality not fully ported.</strong><br>
        <strong>Warning: Setting this field means that groups can be deleted, created or have members added to it!</strong><br> This is optional and used for testing this server\'s group configuration.'),
    ];

    $form['submit'] = [
      '#type' => 'submit',
      '#value' => 'Test',
      '#weight' => 100,
    ];

    if ($form_state->get(['ldap_server_test_data'])) {
      $test_data = $form_state->get(['ldap_server_test_data']);
      $form['#suffix'] = '';

      if (isset($test_data['username']) && isset($test_data['ldap_user'])) {
        $rows = $this->computeUserData($test_data);

        $settings = [
          '#theme' => 'table',
          '#header' => ['Attribute Name', 'Instance', 'Value', 'Token'],
          '#rows' => $rows,
        ];

        $form['#suffix'] .= '<div class="content">
        <h2>' . $this->t('LDAP Entry for %username (dn: %dn)', ['%dn' => $test_data['ldap_user']['dn'], '%username' => $test_data['username']]) . '</h2>'
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
        $settings = [
          '#theme' => 'table',
          '#header' => $table_name == 'basic' ? ['Test'] : ['Test', 'Result'],
          '#rows' => $table_data,
        ];
        $form['#suffix'] .= '<h2>' . $titles[$table_name] . '</h2>' . drupal_render($settings);
      }

      if (!empty($test_data['username'])) {
        $user_name = $test_data['username'];
        if ($user = user_load_by_name($user_name)) {
          $form['#suffix'] .= '<h3>' . $this->t('Corresponding Drupal user object for @user:', ['@user' => $user_name]) . '</h3>';
          $form['#suffix'] .= '<pre>' . json_encode($user->toArray(), JSON_PRETTY_PRINT) . '</pre>';
          $form['#suffix'] .= '<h3>' . $this->t('Corresponding test group LDAP entry:') . '</h3>';
          $form['#suffix'] .= '<pre>' . json_encode($test_data['group_entry'][0], JSON_PRETTY_PRINT) . '</pre>';
        }
      }
    }
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $server = Server::load($values['id']);

    if (!$values['id']) {
      $form_state->setErrorByName(NULL, $this->t('No server id found in form'));
    }
    elseif (!$server) {
      $form_state->setErrorByName(NULL, $this->t('Failed to create server object for server with server id=%id', [
        '%id' => $values['id'],
      ]));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $has_errors = FALSE;

    // Pass data back to form builder.
    $form_state->setRebuild(TRUE);

    $values = $form_state->getValues();
    $id = $values['id'];
    $this->ldapServer = Server::load($id);

    if ($this->ldapServer->get('bind_method') == 'service_account') {
      $this->resultsTables['basic'][] = [$this->t('Binding with DN for non-anonymous search (%bind_dn).', ['%bind_dn' => $this->ldapServer->get('binddn')])];
      $has_errors = $this->testBindingCredentials();
    }
    else {
      $this->resultsTables['basic'][] = [$this->t('Binding with null DN for anonymous search.')];
      $has_errors = $this->testAnonymousBind();
    }

    if ($this->ldapServer->get('bind_method') == 'anon_user') {
      $this->resultsTables['basic'][] = [$this->t('Binding with user credentials (%bind_dn).', ['%bind_dn' => $values['testing_drupal_username']])];
      list($has_errors, $ldap_user) = $this->testUserMapping($values['testing_drupal_username']);
      if (!$has_errors) {
        $mapping[] = "dn = " . $ldap_user['dn'];
        foreach ($ldap_user['attr'] as $key => $value) {
          if (is_array($value)) {
            $mapping[] = "$key = " . $this->binaryCheck($value[0]);
          }
        }

        $item_list = [
          '#list_type' => 'ul',
          '#theme' => 'item_list',
          '#items' => $mapping,
          '#title' => $this->t('Attributes available to anonymous search', [
            '%bind_dn' => $this->ldapServer->get('binddn'),
          ]),
        ];
        $this->resultsTables['basic'][] = [render($item_list)];
      }
      $this->resultsTables['basic'][] = [
        $this->t('Binding with DN (%bind_dn), using supplied password.', [
          '%bind_dn' => $ldap_user['dn'],
        ]),
      ];
      $result = $this->ldapServer->bind($ldap_user['dn'], $values['testing_drupal_userpw'], FALSE);
      if ($result == Server::LDAP_SUCCESS) {
        $this->resultsTables['basic'][] = [
          'class' => 'color-success',
          'data' => [$this->t('Successfully bound to server')],
        ];
      }
      else {
        $this->resultsTables['basic'][] = [
          'class' => 'color-error',
          'data' => [
            $this->t('Failed to bind to server. LDAP error: @error', [
              '@error' => $this->ldapServer->formattedError($result),
            ]
            ),
          ],
        ];
      }
    }

    if (@$values['grp_test_grp_dn_writeable'] && @$values['grp_test_grp_dn']) {
      $this->testwritableGroup($values);
    }

    if (!$has_errors && isset($values['grp_test_grp_dn'])) {
      $user = isset($values['testing_drupal_username']) ? $values['testing_drupal_username'] : NULL;
      $group_entry = $this->testGroupDn($values['grp_test_grp_dn'], $user);
    }

    list($has_errors, $ldap_user) = $this->testUserMapping($values['testing_drupal_username']);
    $tokenHelper = new TokenProcessor();
    $tokens = ($ldap_user && isset($ldap_user['attr'])) ? $tokenHelper->tokenizeEntry($ldap_user['attr'], 'all', TokenProcessor::PREFIX, TokenProcessor::SUFFIX) : [];
    foreach ($tokens as $key => $value) {
      $this->resultsTables['tokens'][] = [$key, $this->binaryCheck($value)];
    }
    $form_state->set(['ldap_server_test_data'], [
      'username' => $values['testing_drupal_username'],
      'results_tables' => $this->resultsTables,
    ]);

    if (isset($ldap_user)) {
      $form_state->set(['ldap_server_test_data', 'ldap_user'], $ldap_user);
    }

    if (isset($group_entry)) {
      $form_state->set(['ldap_server_test_data', 'group_entry'], $group_entry);
    }

  }

  /**
   * Test the Group DN.
   *
   * @param string $group_dn
   *   Group DN.
   * @param mixed|null $user
   *   User? Unknown.
   *
   * @return array
   *   Response.
   */
  private function testGroupDn($group_dn, $user) {
    $group_entry = $this->ldapServer->search($group_dn, 'objectClass=*');

    if ($group_entry) {
      foreach ([FALSE, TRUE] as $nested) {
        // FALSE.
        $nested_display = ($nested) ? 'Yes' : 'No';
        if ($user) {
          // This is the parent function that will call FromUserAttr or
          // FromEntry.
          $memberships = $this->ldapServer->groupMembershipsFromUser($user, $nested);
          $settings = [
            '#theme' => 'item_list',
            '#items' => $memberships,
            '#list_type' => 'ul',
          ];
          $result = drupal_render($settings);

          $this->resultsTables['group2'][] = [
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
            $settings = [
              '#theme' => 'item_list',
              '#items' => $groupUserMembershipsFromUserAttributes,
              '#list_type' => 'ul',
            ];
            $result = drupal_render($settings);

          }
          else {
            $groupUserMembershipsFromUserAttributes = [];
            $result = "'A user LDAP attribute such as memberOf exists that contains a list of their group' is not configured.";
          }
          $this->resultsTables['group2'][] = [
            'Group memberships from user attribute for ' . $user . ' (nested=' . $nested_display . ') (' . count($groupUserMembershipsFromUserAttributes) . ' found)',
            $result,
          ];

          if ($this->ldapServer->groupGroupEntryMembershipsConfigured()) {
            $groupUserMembershipsFromEntry = $this->ldapServer->groupUserMembershipsFromEntry($user, $nested);
            $settings = [
              '#theme' => 'item_list',
              '#items' => $groupUserMembershipsFromEntry,
              '#list_type' => 'ul',
            ];
            $result = drupal_render($settings);

          }
          else {
            $groupUserMembershipsFromEntry = [];
            $result = "Groups by entry not configured.";
          }
          $this->resultsTables['group2'][] = [
            'Group memberships from entry for ' . $user . ' (nested=' . $nested_display . ') (' . count($groupUserMembershipsFromEntry) . ' found)',
            $result,
          ];

          if (count($groupUserMembershipsFromEntry) && count($groupUserMembershipsFromUserAttributes)) {
            $diff1 = array_diff($groupUserMembershipsFromUserAttributes, $groupUserMembershipsFromEntry);
            $diff2 = array_diff($groupUserMembershipsFromEntry, $groupUserMembershipsFromUserAttributes);
            $settings = [
              '#theme' => 'item_list',
              '#items' => $diff1,
              '#list_type' => 'ul',
            ];
            $result1 = drupal_render($settings);

            $settings = [
              '#theme' => 'item_list',
              '#items' => $diff2,
              '#list_type' => 'ul',
            ];
            $result2 = drupal_render($settings);

            $this->resultsTables['group2'][] = [
              "groupUserMembershipsFromEntry and FromUserAttr Diff)",
              $result1,
            ];
            $this->resultsTables['group2'][] = [
              "FromUserAttr and groupUserMembershipsFromEntry Diff)",
              $result2,
            ];
          }
        }
      }
    }

    if ($groups_from_dn = $this->ldapServer->groupUserMembershipsFromDn($user)) {
      $settings = [
        '#theme' => 'item_list',
        '#items' => $groups_from_dn,
        '#list_type' => 'ul',
      ];
      $result = drupal_render($settings);
      $this->resultsTables['groupfromDN'][] = ["Groups from DN", $result];
    }
    return $group_entry;
  }

  /**
   * Check if binary and escape if necessary.
   *
   * @param string $input
   *   Input string.
   *
   * @return \Drupal\Core\StringTranslation\TranslatableMarkup|string
   *   Escaped string.
   */
  public static function binaryCheck($input) {
    if (preg_match('~[^\x20-\x7E\t\r\n]~', $input) > 0) {
      $truncatedString = Unicode::truncate($input, 120, FALSE, TRUE);
      return t('Binary (excerpt): @excerpt', ['@excerpt' => $truncatedString]);
    }
    else {
      return $input;
    }
  }

  /**
   * Add a group entry.
   *
   * @param string $group_dn
   *   The group DN as an LDAP DN.
   * @param array $attributes
   *   Attributes in key value form
   *    $attributes = array(
   *      "attribute1" = "value",
   *      "attribute2" = array("value1", "value2"),
   *      )
   *
   * @return bool
   *   Operation result.
   *
   * @FIXME: NOT TESTED, UNPORTED:
   */
  public function groupAddGroup($group_dn, array $attributes = []) {

    if ($this->ldapServer->dnExists($group_dn, 'boolean')) {
      return FALSE;
    }

    $attributes = array_change_key_case($attributes, CASE_LOWER);
    $objectClass = (empty($attributes['objectclass'])) ? $this->ldapServer->groupObjectClass() : $attributes['objectclass'];
    $attributes['objectclass'] = $objectClass;

    // 2. give other modules a chance to add or alter attributes.
    $context = [
      'action' => 'add',
      'corresponding_drupal_data' => [$group_dn => $attributes],
      'corresponding_drupal_data_type' => 'group',
    ];
    $ldap_entries = [$group_dn => $attributes];
    \Drupal::moduleHandler()->alter('ldap_entry_pre_provision', $ldap_entries, $this, $context);
    $attributes = $ldap_entries[$group_dn];

    // 4. provision LDAP entry.
    // @todo how is error handling done here?
    $ldap_entry_created = $this->ldapServer->createLdapEntry($attributes, $group_dn);

    // 5. allow other modules to react to provisioned LDAP entry.
    //    @todo how is error handling done here?
    if ($ldap_entry_created) {
      \Drupal::moduleHandler()
        ->invokeAll('ldap_entry_post_provision',
          [$ldap_entries, $this, $context]
        );
      return TRUE;
    }
    else {
      return FALSE;
    }

  }

  /**
   * Remove a group entry.
   *
   * @param string $group_dn
   *   Group DN as LDAP dn.
   * @param bool $only_if_group_empty
   *   TRUE = group should not be removed if not empty
   *   FALSE = groups should be deleted regardless of members.
   *
   * @return bool
   *   Removal result.
   *
   * @TODO: NOT TESTED
   */
  public function groupRemoveGroup($group_dn, $only_if_group_empty = TRUE) {

    if ($only_if_group_empty) {
      $members = $this->groupAllMembers($group_dn);
      if (is_array($members) && count($members) > 0) {
        return FALSE;
      }
    }
    // @FIXME: Incorrect parameters
    return $this->ldapServer->deleteLdapEntry($group_dn);

  }

  /**
   * Add a member to a group.
   *
   * @param string $group_dn
   *   LDAP user DN.
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user  or a username.
   *
   * @return bool
   *   Operation successful.
   *
   * @TODO: NOT TESTED
   */
  public function groupAddMember($group_dn, $user) {

    $user_ldap_entry = $this->ldapServer->userUserToExistingLdapEntry($user);
    $result = FALSE;
    if ($user_ldap_entry && $this->ldapServer->groupGroupEntryMembershipsConfigured()) {
      $add = [];
      $add[$this->ldapServer->groupMembershipsAttr()] = $user_ldap_entry['dn'];
      $this->ldapServer->connectAndBindIfNotAlready();
      $result = @ldap_mod_add($this->connection, $group_dn, $add);
    }

    return $result;
  }

  /**
   * Remove a member from a group.
   *
   * @param string $group_dn
   *   Group DN as LDAP DN.
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user  or a username.
   *
   * @return bool
   *   Operation successful.
   *
   * @FIXME: NOT TESTED
   */
  public function groupRemoveMember($group_dn, $user) {

    $user_ldap_entry = $this->ldapServer->userUserToExistingLdapEntry($user);
    $result = FALSE;
    if ($user_ldap_entry && $this->ldapServer->groupGroupEntryMembershipsConfigured()) {
      $del = [];
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
   *
   * @param string $group_dn
   *   Group DN as LDAP DN.
   *
   * @return bool|array
   *   FALSE on error, otherwise array of group members (could be users or
   *   groups).
   *
   * @todo: NOT IMPLEMENTED: nested groups
   */
  public function groupAllMembers($group_dn) {

    if (!$this->ldapServer->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }
    $attributes = [$this->ldapServer->groupMembershipsAttr(), 'cn'];
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
        return [];
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
   * Test the user mappings.
   *
   * @param string $drupal_username
   *   The Drupal username.
   *
   * @return array
   *   Errors and the user.
   */
  public function testUserMapping($drupal_username) {
    $ldap_user = $this->ldapServer->matchUsernameToExistingLdapEntry($drupal_username);

    $errors = FALSE;
    if (!$ldap_user) {
      $this->resultsTables['basic'][] = [
        'class' => 'color-error',
        'data' => [t('Failed to find test user %username by searching on %user_attr = %username.',
          [
            '%username' => $drupal_username,
            '%user_attr' => $this->ldapServer->get('user_attr'),
          ]
          ),
        ],
      ];
      $errors = TRUE;
    }
    else {
      $this->resultsTables['basic'][] = [
        'class' => 'color-success',
        'data' => [
          $this->t('Found test user %username by searching on  %user_attr = %username.',
            ['%username' => $drupal_username, '%user_attr' => $this->ldapServer->get('user_attr')]
          ),
        ],
      ];
    }
    return [$errors, $ldap_user];
  }

  /**
   * Test writable groups.
   *
   * @param array $values
   *   Group data.
   *
   * @TODO: Unported.
   */
  private function testwritableGroup(array $values) {
    $user_test_dn = @$values['grp_test_grp_dn'];
    $group_create_test_dn = $values['grp_test_grp_dn_writeable'];
    $group_create_test_attr = [
      'objectClass' => [
        $this->ldapServer->get('grp_object_cat'),
        'top',
      ],
    ];

    // 1. delete test group if it exists.
    if ($this->ldapServer->dnExists($group_create_test_dn, 'ldap_entry', ['cn', 'member'])
    ) {
      $this->groupRemoveGroup($group_create_test_dn, FALSE);
    }

    $group_exists = $this->ldapServer->dnExists($group_create_test_dn, 'ldap_entry', [
      'cn',
      'member',
    ]);
    $result = ($group_exists === FALSE) ? "PASS" : "FAIL";
    $this->resultsTables['group1'][] = [
      "Starting test without group: $group_create_test_dn ",
      $result,
    ];

    // 2. make sure call to members in empty group returns false.
    $result = $this->groupAllMembers($group_create_test_dn);
    $result = ($result === FALSE) ? "PASS" : 'FAIL';
    $this->resultsTables['group1'][] = [
      "LdapServer::groupAllMembers($group_create_test_dn) call on nonexistent group returns FALSE",
      $result,
    ];

    // 3. add group.
    $result = $this->groupAddGroup($group_create_test_dn, $group_create_test_attr);
    $result = ($result) ? "PASS" : 'FAIL';
    $attr = serialize($group_create_test_attr);
    $this->resultsTables['group1'][] = [
      "LdapServer::groupAddGroup($group_create_test_dn, $attr)",
      $result,
    ];

    // 4. call to all members in an empty group returns emtpy array, not FALSE.
    $result = $this->groupAllMembers($group_create_test_dn);
    $result = (is_array($result) && count($result) == 0) ? 'PASS' : 'FAIL';
    $this->resultsTables['group1'][] = [
      "LdapServer::groupAllMembers($group_create_test_dn) returns empty array for empty group ",
      $result,
    ];

    // 5. add member to group.
    $this->groupAddMember($group_create_test_dn, $user_test_dn);
    $result = is_array($this->groupAllMembers($group_create_test_dn)) ? 'PASS' : 'FAIL';
    $this->resultsTables['group1'][] = [
      "LdapServer::groupAddMember($group_create_test_dn, $user_test_dn)",
      $result,
    ];

    // 6. try to remove group with member in it.
    $only_if_group_empty = TRUE;
    $result = $this->groupRemoveGroup($group_create_test_dn, $only_if_group_empty);
    $result = ($result) ? 'FAIL' : 'PASS';
    $this->resultsTables['group1'][] = [
      "LdapServer::groupRemoveGroup($group_create_test_dn, $only_if_group_empty)",
      $result,
    ];

    // 7. remove group member.
    $this->groupRemoveMember($group_create_test_dn, $user_test_dn);
    $result = $this->groupAllMembers($group_create_test_dn);
    $result = (is_array($result) && count($result) == 0) ? 'PASS' : 'FAIL';
    $this->resultsTables['group1'][] = [
      "LdapServer::groupRemoveMember($group_create_test_dn, $user_test_dn)",
      $result,
    ];

    $only_if_group_empty = TRUE;
    $this->groupRemoveGroup($group_create_test_dn, $only_if_group_empty);
    $result = ($this->ldapServer->dnExists($group_create_test_dn, 'ldap_entry', [
      'cn',
      'member',
    ])) ? "FAIL" : 'PASS';
    $this->resultsTables['group1'][] = [
      "LdapServer::groupRemoveGroup($group_create_test_dn, $only_if_group_empty)",
      $result,
    ];
  }

  /**
   * Test anonymous binding.
   *
   * @return bool
   *   Binding successful.
   */
  private function testAnonymousBind() {
    $result = FALSE;
    $ldap_result = $this->ldapServer->connect();

    if ($ldap_result != Server::LDAP_SUCCESS) {

      $this->resultsTables['basic'][] = [
        'class' => 'color-error',
        'data' => [t('Failed to connect to LDAP server: @error', $this->ldapServer->formattedError($ldap_result))],
      ];
      $result = TRUE;
    }

    if (!$result) {
      $bind_result = $this->ldapServer->bind(NULL, NULL, TRUE);
      if ($bind_result == Server::LDAP_SUCCESS) {
        $this->resultsTables['basic'][] = [
          'class' => 'color-success',
          'data' => [t('Successfully bound to server')],
        ];
      }
      else {
        $this->resultsTables['basic'][] = [
          'class' => 'color-error',
          'data' => [t('Failed to bind anonymously. LDAP error: @error', ['@error' => $this->ldapServer->formattedError($bind_result)])],
        ];
        $result = TRUE;
      }
    }
    else {
      $this->resultsTables['basic'][] = [t('No service account set to bind with.')];
    }
    return $result;
  }

  /**
   * Helper function to bind as required for testing.
   */
  public function testBindingCredentials() {
    $errors = FALSE;
    $ldap_result = $this->ldapServer->connect();

    if ($ldap_result != Server::LDAP_SUCCESS) {

      $this->resultsTables['basic'][] = [
        'class' => 'color-error',
        'data' => [t('Failed to connect to LDAP server: @error', $this->ldapServer->formattedError($ldap_result))],
      ];
      $errors = TRUE;
    }

    if (!$errors) {
      if (!empty($this->ldapServer->get('binddn')) && !empty($this->ldapServer->get('bindpw'))) {
        $bind_result = $this->ldapServer->bind($this->ldapServer->get('binddn'), $this->ldapServer->get('bindpw'), FALSE);
        if ($bind_result == Server::LDAP_SUCCESS) {
          $this->resultsTables['basic'][] = [
            'class' => 'color-success',
            'data' => [t('Successfully bound to server')],
          ];
        }
        else {
          $this->resultsTables['basic'][] = [
            'class' => 'color-error',
            'data' => [t('Failed to bind with service account. LDAP error: @error', ['@error' => $this->ldapServer->formattedError($bind_result)])],
          ];
          $errors = TRUE;
        }
      }
      else {
        $this->resultsTables['basic'][] = [t('No service account set to bind with.')];
      }
    }
    return $errors;
  }

  /**
   * Compute user data.
   *
   * @param array $test_data
   *   Data to test on.
   *
   * @return array
   *   Computed data.
   */
  private function computeUserData(array $test_data) {
    $rows = [];
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
            $token = TokenProcessor::PREFIX . $key . TokenProcessor::SUFFIX;
          }
          elseif ($i == 0 && $count > 1) {
            $token = TokenProcessor::PREFIX . $key . TokenProcessor::DELIMITER . '0' . TokenProcessor::SUFFIX;
          }
          elseif (($i == $count - 1) && $count > 1) {
            $token = TokenProcessor::PREFIX . $key . TokenProcessor::DELIMITER . 'last' . TokenProcessor::SUFFIX;
          }
          elseif ($count > 1) {
            $token = TokenProcessor::PREFIX . $key . TokenProcessor::DELIMITER . $i . TokenProcessor::SUFFIX;
          }
          else {
            $token = "";
          }
          $rows[] = ['data' => [$key, $i, self::binaryCheck($value2), $token]];
        }
      }
    }
    return $rows;
  }

}
