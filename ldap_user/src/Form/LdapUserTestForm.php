<?php

namespace Drupal\ldap_user\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;
use Drupal\ldap_user\LdapUserConf;
use Drupal\user\Entity\User;
use PDO;

/**
 *
 */
class LdapUserTestForm extends FormBase {

  private static $sync_trigger_options;

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_user_test_form';
  }

  /**
   * {@inheritdoc}
   */
  public function __construct() {
    $this::$sync_trigger_options = [
      LdapUserConf::$provisionDrupalUserOnUserUpdateCreate => t('On sync to Drupal user create or update. Requires a server with binding method of "Service Account Bind" or "Anonymous Bind".'),
      LdapUserConf::$provisionDrupalUserOnAuthentication => t('On create or sync to Drupal user when successfully authenticated with LDAP credentials. (Requires LDAP Authentication module).'),
      LdapUserConf::$provisionDrupalUserOnAllowingManualCreation => t('On manual creation of Drupal user from admin/people/create and "Create corresponding LDAP entry" is checked'),
      LdapUserConf::$provisionLdapEntryOnUserUpdateCreate => t('On creation or sync of an LDAP entry when a Drupal account is created or updated. Only applied to accounts with a status of approved.'),
      LdapUserConf::$provisionLdapEntryOnUserAuthentication => t('On creation or sync of an LDAP entry when a user authenticates.'),
      LdapUserConf::$provisionLdapEntryOnUserDelete => t('On deletion of an LDAP entry when the corresponding Drupal Account is deleted.  This only applies when the LDAP entry was provisioned by Drupal by the LDAP User module.'),
    ];
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state, $op = NULL) {

    $username = @$_SESSION['ldap_user_test_form']['testing_drupal_username'];

    $form['#prefix'] = t('<h1>Test LDAP User Configuration</h1>');

    $form['#prefix'] .= t('This form simply tests an LDAP User configuration against an individual ldap or drupal user.
    It makes no changes to the drupal or ldap user.');

    $form['testing_drupal_username'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Drupal Username'),
      '#default_value' => $username,
      '#required' => 1,
      '#size' => 30,
      '#maxlength' => 255,
      '#description' => t('This is optional and used for testing this server\'s configuration against an actual username.  The user need not exist in Drupal and testing will not affect the user\'s LDAP or Drupal Account.'),
    ];

    $form['test_mode'] = [
      '#type' => 'radios',
      '#title' => t('Testing Mode'),
      '#required' => 0,
      '#default_value' => isset($_SESSION['ldap_user_test_form']['test_mode']) ? $_SESSION['ldap_user_test_form']['test_mode'] : 'query',
      '#options' => [
        'query' => t('Test Query.  Will not alter anything in drupal or LDAP'),
        'execute' => t('Execute Action.  Will perform provisioning configured for events below.  If this is selected only one action should be selected below'),
      ],
    ];

    $selected_actions = isset($_SESSION['ldap_user_test_form']['action']) ? $_SESSION['ldap_user_test_form']['action'] : [];
    $form['action'] = [
      '#type' => 'checkboxes',
      '#title' => t('Actions/Event Handlers to Test'),
      '#required' => 0,
      '#default_value' => $selected_actions,
      '#options' => self::$sync_trigger_options,
    ];

    $form['submit'] = [
      '#type' => 'submit',
      '#value' => 'test',
      '#weight' => 100,
    ];

    return $form;
  }

  /**
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    if ($form_state->getValue(['test_mode']) == 'execute' && count(array_filter($form_state->getValue([
      'action',
    ]))) > 1) {
      $form_state->setErrorByName('test_mode', t('Only one action may be selected for "Execute Action" testing mode.'));
    }

  }

  /**
   *
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $username = $form_state->getValue(['testing_drupal_username']);
    $selected_actions = $form_state->getValue(['action']);

    if ($username && count($selected_actions) > 0) {

      /* @var User $account */
      $account = user_load_by_name($username);

      $ldap_user_conf = new LdapUserConf();
      $config = \Drupal::config('ldap_user.settings')->get('ldap_user_conf');

      $test_servers = [];
      $user_ldap_entry = FALSE;
      $factory = \Drupal::service('ldap.servers');

      if ($config['drupalAcctProvisionServer']) {
        $test_servers[LdapUserConf::$provisioningDirectionToDrupalUser] = $config['drupalAcctProvisionServer'];
        $user_ldap_entry = $factory->getUserDataFromServerByIdentifier($username, $config['drupalAcctProvisionServer']);
      }
      if ($config['ldapEntryProvisionServer']) {
        $test_servers[LdapUserConf::$provisioningDirectionToLDAPEntry] = $config['ldapEntryProvisionServer'];
        if (!$user_ldap_entry) {
          $user_ldap_entry = $factory->getUserDataFromServerByIdentifier($username, $config['ldapEntryProvisionServer']);
        }
      }
      $results = [];
      $results['username'] = $username;
      $results['user entity (before provisioning or syncing)'] = $account;
      $results['related ldap entry (before provisioning or syncing)'] = $user_ldap_entry;
      $results['ldap_user_conf'] = $ldap_user_conf;

      if (is_object($account)) {
        $authmaps = LdapUserConf::getUserIdentifierFromMap($account->id());
      }
      else {
        $authmaps = 'No authmaps available.  Authmaps only shown if user account exists beforehand';
        // Need for testing.
        $account = User::create();
        $account->setUsername($username);

      }
      $results['User Authmap'] = $authmaps;
      $results['LDAP User Configuration Object'] = $ldap_user_conf;

      $save = ($form_state->getValue(['test_mode']) == 'execute');
      $test_query = ($form_state->getValue(['test_mode']) != 'execute');
      $account = ['name' => $username];

      foreach (array_filter($selected_actions) as $i => $sync_trigger) {
        $sync_trigger_description = self::$sync_trigger_options[$sync_trigger];
        foreach ([
          LdapUserConf::$provisioningDirectionToDrupalUser,
          LdapUserConf::$provisioningDirectionToLDAPEntry,
        ] as $direction) {
          if ($ldap_user_conf->provisionEnabled($direction, $sync_trigger)) {
            if ($direction == LdapUserConf::$provisioningDirectionToDrupalUser) {
              $ldap_user_conf->provisionDrupalAccount(NULL, $account, NULL, $save);
              $results['provisionDrupalAccount method results']["context = $sync_trigger_description"]['proposed'] = $account;
            }
            else {
              $provision_result = $ldap_user_conf->provisionLdapEntry($account, NULL, $test_query);
              $results['provisionLdapEntry method results']["context = $sync_trigger_description"] = $provision_result;
            }
          }
          else {
            if ($direction == LdapUserConf::$provisioningDirectionToDrupalUser) {
              $results['provisionDrupalAccount method results']["context = $sync_trigger_description"] = 'Not enabled.';
            }
            else {
              $results['provisionLdapEntry method results']["context = $sync_trigger_description"] = 'Not enabled.';
            }
          }
        }
      }
      // Do all syncs second, in case logic of form changes to allow executing mulitple events.
      foreach (array_filter($selected_actions) as $i => $sync_trigger) {
        $sync_trigger_description = self::$sync_trigger_options[$sync_trigger];
        foreach ([
          LdapUserConf::$provisioningDirectionToDrupalUser,
          LdapUserConf::$provisioningDirectionToLDAPEntry,
        ] as $direction) {
          if ($ldap_user_conf->provisionEnabled($direction, $sync_trigger)) {
            if ($direction == LdapUserConf::$provisioningDirectionToDrupalUser) {
              $ldap_user_conf->syncToDrupalAccount($account, NULL, $test_query);
              $results['syncToDrupalAccount method results']["context = $sync_trigger_description"]['proposed'] = $account;
            }
            else {
              // To ldap.
              $provision_result = $ldap_user_conf->syncToLdapEntry($account, [], $test_query);
              $results['syncToLdapEntry method results']["context = $sync_trigger_description"] = $provision_result;
            }
          }
          else {
            if ($direction == LdapUserConf::$provisioningDirectionToDrupalUser) {
              $results['syncToDrupalAccount method results']["context = $sync_trigger_description"] = 'Not enabled.';
            }
            else {
              // To ldap.
              $results['syncToLdapEntry method results']["context = $sync_trigger_description"] = 'Not enabled.';
            }
          }
        }
      }

      if (function_exists('dpm')) {
        dpm($results);
      }
      else {
        drupal_set_message(t('This form will not display results unless the devel module is enabled.'), 'warning');
      }
    }

    $_SESSION['ldap_user_test_form']['action'] = $form_state->getValue(['action']);
    $_SESSION['ldap_user_test_form']['test_mode'] = $form_state->getValue(['test_mode']);
    $_SESSION['ldap_user_test_form']['testing_drupal_username'] = $username;

    $form_state->set(['redirect'], 'admin/config/people/ldap/user/test');

  }

}
