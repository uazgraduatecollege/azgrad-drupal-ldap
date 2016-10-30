<?php

namespace Drupal\ldap_servers\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Entity\EntityForm;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_servers\TokenFunctions;

/**
 * Use Drupal\Core\Form\FormBase;.
 */
class ServerTestForm extends EntityForm {
  use TokenFunctions;
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
    // @FIXME
    // drupal_set_title() has been removed. There are now a few ways to set the title
    // dynamically, depending on the situation.
    //
    //
    // @see https://www.drupal.org/node/2067859
    // drupal_set_title(t('Test LDAP Server Configuration: !server', array('!server' => $ldap_server->name)));
    $form['#prefix'] = t('This form tests an LDAP configuration to see if
    it can bind and basic user and group functions.  It also shows token examples
    and a sample user.  The only data this function will modify is the test LDAP group, which will be deleted and added');

    $variables = [
      'ldap_server' => $ldap_server,
      'actions' => FALSE,
      'type' => 'detail',
    ];

    // This used to be done by ldap_servers_server
    // Iterate over Entity fields.
    $entity_type_id = 'ldap_server';
    $properties = array();

    // Foreach (\Drupal::entityManager()->getFieldDefinitions($entity_type_id) as $field_name => $field_definition) {
    //   $properties[] = "$field_name = " . print_r($ldap_server->$field_name->value, TRUE);
    // }.
    $settings = array(
      '#theme' => 'item_list',
      '#items' => $properties,
      '#type' => 'ul',
    );
    $form['server_variables'] = array(
      '#markup' => drupal_render($settings),
    );

    $form['id'] = [
      '#type' => 'hidden',
      '#title' => t('Machine name for this server'),
      '#default_value' => $ldap_server->id(),
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
      '#default_value' => $ldap_server->get('testing_drupal_username'),
      '#size' => 30,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s configuration against an actual username.  The user need not exist in Drupal and testing will not affect the user\'s LDAP or Drupal Account.'),
    ];

    $form['testing_drupal_user_dn'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Drupal DN'),
      '#default_value' => $ldap_server->get('testing_drupal_user_dn'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s configuration against an actual username.  The user need not exist in Drupal and testing will not affect the user\'s LDAP or Drupal Account.'),
    ];

    $form['grp_test_grp_dn'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Group DN'),
      '#default_value' => $ldap_server->get('grp_test_grp_dn'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s group configuration.'),
    ];

    $form['grp_test_grp_dn_writeable'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Group DN that is writeable. Warning!  In test, this group will be deleted, created, have members added to it!'),
      '#default_value' => $ldap_server->get('grp_test_grp_dn_writeable'),
      '#size' => 120,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s group configuration.'),
    ];

    if ($ldap_server->get('bind_method') == Server::$bindMethodAnonUser) {
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
                $token = self::$token_pre . $key . self::$token_post;
              }
              elseif ($i == 0 && $count > 1) {
                $token = self::$token_pre . $key . self::$token_del . '0' . self::$token_post;
              }
              elseif (($i == $count - 1) && $count > 1) {
                $token = self::$token_pre . $key . self::$token_del . 'last' . self::$token_post;
              }
              elseif ($count > 1) {
                $token = self::$token_pre . $key . self::$token_del . $i . self::$token_post;
              }
              else {
                $token = "";
              }
              $rows[] = array('data' => array($key, $i, $value2, $token));
            }
          }
        }

        $settings = array(
          '#theme' => 'table',
          '#header' => $header,
          '#rows' => $rows,
        );

        $form['#prefix']  = '<div class="content"><h2>' . t('LDAP Entry for %username (dn: %dn)', array('%dn' => $test_data['ldap_user']['dn'], '%username' => $test_data['username'])) . '</h2>' . drupal_render($settings) . '</div>';
      }

      $titles = [
        'basic' => 'Test Results',
        'group1' => 'Group Create, Delete, Add Member, Remove Member Tests',
        'group2' => 'User Group Membership Functions Test',
        'tokens' => 'User Token Samples',
        'groupfromDN' => 'Groups Derived From User DN',
      ];

      foreach ($test_data['results_tables'] as $table_name => $table_data) {
        // @FIXME
        // theme() has been renamed to _theme() and should NEVER be called directly.
        // Calling _theme() directly can alter the expected output and potentially
        // introduce security issues (see https://www.drupal.org/node/2195739). You
        // should use renderable arrays instead.
        //
        //
        // @see https://www.drupal.org/node/2195739
        // $form['#prefix'] .= '<h2>' . $titles[$table_name] . '</h2>' . theme('table', array('header' => array('Test', 'Result'), 'rows' => $table_data));
        $settings = array(
          '#type' => 'table',
          '#header' => array('Test', 'Result'),
          '#rows' => $table_data,
        );
        $form['#prefix'] .= '<h2>' . $titles[$table_name] . '</h2>' . drupal_render($settings);
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
          //@FIXME: group_entry is undefined.
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
    $factory = new ServerFactory($values['id'], 'all', TRUE);

    if (!$values['id']) {
      $form_state->setErrorByName(NULL, t('No server id found in form'));
    }
    elseif (!$factory->servers ) {
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
    /* @var \Drupal\ldap_servers\Entity\Server $ldap_server */
    $factory = new ServerFactory($id, 'all', TRUE);
    $ldap_server = $factory->servers;

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

    if ($ldap_server->get('bind_method') == Server::$bindMethodServiceAccount) {
      $results_tables['basic'][] = [
        t('Binding with DN for non-anonymous search (%bind_dn).  Using password ', [
          '%bind_dn' => $ldap_server->get('binddn'),
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
          $ldap_server->get('grp_object_cat'),
          'top',
        ],
      ];

      // 1. delete test group if it exists.
      if ($ldap_server->dnExists($group_create_test_dn, 'ldap_entry', [
        'cn',
        'member',
      ])) {
        $result = $ldap_server->groupRemoveGroup($group_create_test_dn, FALSE);
      }

      $group_exists = $ldap_server->dnExists($group_create_test_dn, 'ldap_entry', [
        'cn',
        'member',
      ]);
      $result = ($group_exists === FALSE) ? "PASS" : "FAIL";
      $results_tables['group1'][] = [
        "Starting test without group: $group_create_test_dn ",
        $result,
      ];

      // 2. make sure call to members in empty group returns false.
      $result = $ldap_server->groupAllMembers($group_create_test_dn);
      $result = ($result === FALSE) ? "PASS" : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupAllMembers($group_create_test_dn) call on nonexistent group returns FALSE",
        $result,
      ];

      // 3. add group.
      $result = $ldap_server->groupAddGroup($group_create_test_dn, $group_create_test_attr);
      $result = ($result) ? "PASS" : 'FAIL';
      $attr = serialize($group_create_test_attr);
      $results_tables['group1'][] = [
        "LdapServer::groupAddGroup($group_create_test_dn, $attr)",
        $result,
      ];

      // 4. call to all members in an empty group returns emtpy array, not FALSE.
      $result = $ldap_server->groupAllMembers($group_create_test_dn);
      $result = (is_array($result) && count($result) == 0) ? 'PASS' : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupAllMembers($group_create_test_dn) returns empty array for empty group ",
        $result,
      ];

      // 5. add member to group.
      $result = $ldap_server->groupAddMember($group_create_test_dn, $user_test_dn);
      $result = is_array($ldap_server->groupAllMembers($group_create_test_dn)) ? 'PASS' : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupAddMember($group_create_test_dn, $user_test_dn)",
        $result,
      ];

      // 6. try to remove group with member in it.
      $only_if_group_empty = TRUE;
      $result = $ldap_server->groupRemoveGroup($group_create_test_dn, $only_if_group_empty);
      $result = ($result) ? 'FAIL' : 'PASS';
      $results_tables['group1'][] = [
        "LdapServer::groupRemoveGroup($group_create_test_dn, $only_if_group_empty)",
        $result,
      ];

      // 7. remove group member.
      $result = $ldap_server->groupRemoveMember($group_create_test_dn, $user_test_dn);
      $result = $ldap_server->groupAllMembers($group_create_test_dn);
      $result = (is_array($result) && count($result) == 0) ? 'PASS' : 'FAIL';
      $results_tables['group1'][] = [
        "LdapServer::groupRemoveMember($group_create_test_dn, $user_test_dn)",
        $result,
      ];

      $only_if_group_empty = TRUE;
      $result = $ldap_server->groupRemoveGroup($group_create_test_dn, $only_if_group_empty);
      $result = ($ldap_server->dnExists($group_create_test_dn, 'ldap_entry', [
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
    list($has_errors, $more_results) = $ldap_server->testBindingCredentials($bindpw, $results_tables);

    $results = array_merge($results, $more_results);

    if ($ldap_server->get('bind_method') == Server::$bindMethodAnonUser) {
      drupal_set_message('Bind method anonymous, user.');
      list($has_errors, $more_results, $ldap_user) = $ldap_server->testUserMapping($values['testing_drupal_username']);
      $results = array_merge($results, $more_results);
      if (!$has_errors) {
        $mapping[] = "dn = " . $ldap_user['dn'];
        foreach ($ldap_user['attr'] as $key => $value) {
          if (is_array($value)) {
            $mapping[] = "$key = " . $value[0];
          }
        }

        $item_list = array(
          'type' => 'ul',
          '#theme' => 'item_list',
          '#items' => $mapping,
          '#title' => t('Attributes available to anonymous search', [
            '%bind_dn' => $ldap_server->get('binddn'),
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
      $result = $ldap_server->bind($ldap_user['dn'], $values['testing_drupal_userpw'], FALSE);
      if ($result == $ldap_server::LDAP_SUCCESS) {
        $results_tables['basic'][] = [t('Successfully bound to server'), t('PASS')];
      }
      else {
        $results_tables['basic'][] = [
          t('Failed to bind to server. ldap error #') . $result . ' ' . $ldap_server->errorMsg('ldap'),
          t('FAIL'),
        ];
      }
    }

    // @FIXME: The following subsesction is disabled until fixed.
    if (!$has_errors && isset($values['grp_test_grp_dn'])) {
      $group_dn = $values['grp_test_grp_dn'];

      /*
      $result = @ldap_read($ldap_server->connection, $group_dn, 'objectClass=*');
      $group_entry = ldap_get_entries($ldap_server->connection, $result);
      $user = isset($values['testing_drupal_username']) ? $values['testing_drupal_username'] : NULL;

      foreach ([FALSE, TRUE] as $nested) {
        // FALSE.
        $nested_display = ($nested) ? 'Yes' : 'No';
        if ($user) {
          // This is the parent function that will call FromUserAttr or FromEntry.
          $memberships = $ldap_server->groupMembershipsFromUser($user, 'group_dns', $nested);
          // @FIXME
          // theme() has been renamed to _theme() and should NEVER be called directly.
          // Calling _theme() directly can alter the expected output and potentially
          // introduce security issues (see https://www.drupal.org/node/2195739). You
          // should use renderable arrays instead.
          //
          //
          // @see https://www.drupal.org/node/2195739
          // $result = theme('item_list', array('items' => $memberships, 'type' => 'ul'));
          $settings = array(
            '#theme' => 'item_list',
            '#items' => $memberships,
            '#type' => 'ul',
          );
          $result = drupal_render($settings);

          $results_tables['group2'][] = [
            "ldap_server->groupMembershipsFromUser($user, 'group_dns', nested=$nested_display)<br>count=" . count($memberships),
            $result,
          ];

          $result = ($ldap_server->groupIsMember($group_dn, $user, $nested)) ? 'Yes' : 'No';
          $group_results[] = [
            "ldap_server->groupIsMember($group_dn, $user, nested=$nested_display)",
            $result,
          ];

          if ($ldap_server->groupUserMembershipsConfigured()) {
            $groupusermembershipsfromuserattr = $ldap_server->groupUserMembershipsFromUserAttr($user, $nested);
            $count = count($groupusermembershipsfromuserattr);
            // @FIXME
            // theme() has been renamed to _theme() and should NEVER be called directly.
            // Calling _theme() directly can alter the expected output and potentially
            // introduce security issues (see https://www.drupal.org/node/2195739). You
            // should use renderable arrays instead.
            //
            //
            // @see https://www.drupal.org/node/2195739
            // $result = theme('item_list', array('items' => $groupusermembershipsfromuserattr, 'type' => 'ul'));
            $settings = array(
              '#theme' => 'item_list',
              '#items' => $groupusermembershipsfromuserattr,
              '#type' => 'ul',
            );
            $result = drupal_render($settings);

          }
          else {
            $groupusermembershipsfromuserattr = [];
            $result = "'A user LDAP attribute such as memberOf exists that contains a list of their group' is not configured.";
          }
          $results_tables['group2'][] = [
            "ldap_server->groupUserMembershipsFromUserAttr($user, nested=$nested_display)<br> count=" . count($groupusermembershipsfromuserattr),
            $result,
          ];

          if ($ldap_server->groupGroupEntryMembershipsConfigured()) {
            $groupusermembershipsfromentry = $ldap_server->groupUserMembershipsFromEntry($user, $nested);
            // @FIXME
            // theme() has been renamed to _theme() and should NEVER be called directly.
            // Calling _theme() directly can alter the expected output and potentially
            // introduce security issues (see https://www.drupal.org/node/2195739). You
            // should use renderable arrays instead.
            //
            //
            // @see https://www.drupal.org/node/2195739
            // $result = theme('item_list', array('items' => $groupusermembershipsfromentry, 'type' => 'ul'));
            $settings = array(
              '#theme' => 'item_list',
              '#items' => $groupusermembershipsfromentry,
              '#type' => 'ul',
            );
            $result = drupal_render($settings);

          }
          else {
            $groupusermembershipsfromentry = [];
            $result = "Groups by entry not configured.";
          }
          $results_tables['group2'][] = [
            "ldap_server->groupUserMembershipsFromEntry($user, nested=$nested_display)<br>count=" . count($groupusermembershipsfromentry),
            $result,
          ];

          if (count($groupusermembershipsfromentry) && count($groupusermembershipsfromuserattr)) {
            $diff1 = array_diff($groupusermembershipsfromuserattr, $groupusermembershipsfromentry);
            $diff2 = array_diff($groupusermembershipsfromentry, $groupusermembershipsfromuserattr);
            // @FIXME
            // theme() has been renamed to _theme() and should NEVER be called directly.
            // Calling _theme() directly can alter the expected output and potentially
            // introduce security issues (see https://www.drupal.org/node/2195739). You
            // should use renderable arrays instead.
            //
            //
            // @see https://www.drupal.org/node/2195739
            // $result1 = theme('item_list', array('items' => $diff1, 'type' => 'ul'));
            $settings = array(
              '#theme' => 'item_list',
              '#items' => $diff1,
              '#type' => 'ul',
            );
            $result1 = drupal_render($settings);

            // @FIXME
            // theme() has been renamed to _theme() and should NEVER be called directly.
            // Calling _theme() directly can alter the expected output and potentially
            // introduce security issues (see https://www.drupal.org/node/2195739). You
            // should use renderable arrays instead.
            //
            //
            // @see https://www.drupal.org/node/2195739
            // $result2 = theme('item_list', array('items' => $diff2, 'type' => 'ul'));
            $settings = array(
              '#theme' => 'item_list',
              '#items' => $diff2,
              '#type' => 'ul',
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

      if ($groups_from_dn = $ldap_server->groupUserMembershipsFromDn($user)) {
        // @FIXME
        // theme() has been renamed to _theme() and should NEVER be called directly.
        // Calling _theme() directly can alter the expected output and potentially
        // introduce security issues (see https://www.drupal.org/node/2195739). You
        // should use renderable arrays instead.
        //
        //
        // @see https://www.drupal.org/node/2195739
        // $results_tables['groupfromDN'][] = array("Groups from DN", theme('item_list', array('items' => $groups_from_dn, 'type' => 'ul')));
        $settings = array(
          '#theme' => 'item_list',
          '#items' => $groups_from_dn,
          '#type' => 'ul',
        );
        $result = drupal_render($settings);
        $results_tables['groupfromDN'][] = array("Groups from DN", $result);

      }
*/
    }

    list($has_errors, $more_results, $ldap_user) = $ldap_server->testUserMapping($values['testing_drupal_username']);

    $tokens = ($ldap_user && isset($ldap_user['attr'])) ? $this->tokenizeEntry($ldap_user['attr'], 'all') : [];
    foreach ($tokens as $key => $value) {
      $results_tables['tokens'][] = [$key, $value];
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

}
