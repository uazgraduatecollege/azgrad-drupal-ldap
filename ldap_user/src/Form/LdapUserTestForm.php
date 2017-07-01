<?php

namespace Drupal\ldap_user\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Processor\DrupalUserProcessor;
use Drupal\ldap_user\Processor\LdapUserProcessor;

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
      LdapConfiguration::PROVISION_DRUPAL_USER_ON_USER_UPDATE_CREATE => t('On sync to Drupal user create or update. Requires a server with binding method of "Service Account Bind" or "Anonymous Bind".'),
      LdapConfiguration::PROVISION_DRUPAL_USER_ON_USER_AUTHENTICATION => t('On create or sync to Drupal user when successfully authenticated with LDAP credentials. (Requires LDAP Authentication module).'),
      LdapConfiguration::PROVISION_DRUPAL_USER_ON_USER_ON_MANUAL_CREATION => t('On manual creation of Drupal user from admin/people/create and "Create corresponding LDAP entry" is checked'),
      LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE => t('On creation or sync of an LDAP entry when a Drupal account is created or updated. Only applied to accounts with a status of approved.'),
      LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION => t('On creation or sync of an LDAP entry when a user authenticates.'),
      LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE => t('On deletion of an LDAP entry when the corresponding Drupal Account is deleted.  This only applies when the LDAP entry was provisioned by Drupal by the LDAP User module.'),
    ];
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state, $op = NULL) {

    $username = @$_SESSION['ldap_user_test_form']['testing_drupal_username'];

    $form['#prefix'] = t('<h1>Debug LDAP synchronization events</h1>');

    $form['usage'] = [
      '#markup' => t('This form is for debugging issues with specific provisioning events. If you want to test your setup in general, try the server\'s test page first.'),
    ];
    $form['warning'] = [
      '#markup' => '<h3>' . $this->t('If you trigger the event this will modify your data.') . '</h3>' . $this->t('When in doubt, always work on a staging environment.'),
    ];

    $form['testing_drupal_username'] = [
      '#type' => 'textfield',
      '#title' => t('Testing Drupal Username'),
      '#default_value' => $username,
      '#required' => 1,
      '#size' => 30,
      '#maxlength' => 255,
      '#description' => t('The user need not exist in Drupal and testing will not affect the user\'s LDAP or Drupal Account.'),
    ];

    $selected_actions = isset($_SESSION['ldap_user_test_form']['action']) ? $_SESSION['ldap_user_test_form']['action'] : [];
    $form['action'] = [
      '#type' => 'radios',
      '#title' => t('Actions/Event Handler to Test'),
      '#required' => 0,
      '#default_value' => $selected_actions,
      '#options' => self::$sync_trigger_options,
    ];

    $form['submit'] = [
      '#type' => 'submit',
      '#value' => t('Test'),
      '#weight' => 100,
    ];

    return $form;
  }

  /**
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    if (count(array_filter($form_state->getValue(['action']))) > 1) {
      $form_state->setErrorByName(
        'action',
        t('Only one action may be selected for "Execute Action" testing mode.')
      );
    }

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $username = $form_state->getValue(['testing_drupal_username']);
    $selected_action = $form_state->getValue(['action']);

    if ($username && count($selected_action) > 0) {

      $config = \Drupal::config('ldap_user.settings')->get();
      $processor = new DrupalUserProcessor();
      $ldapProcessor = new LdapUserProcessor();

      $test_servers = [];
      $user_ldap_entry = FALSE;
      $factory = \Drupal::service('ldap.servers');

      if ($config['drupalAcctProvisionServer']) {
        $test_servers[LdapConfiguration::PROVISION_TO_DRUPAL] = $config['drupalAcctProvisionServer'];
        $user_ldap_entry = $factory->getUserDataFromServerByIdentifier($username, $config['drupalAcctProvisionServer']);
      }
      if ($config['ldapEntryProvisionServer']) {
        $test_servers[LdapConfiguration::PROVISION_TO_LDAP] = $config['ldapEntryProvisionServer'];
        if (!$user_ldap_entry) {
          $user_ldap_entry = $factory->getUserDataFromServerByIdentifier($username, $config['ldapEntryProvisionServer']);
        }
      }
      $results = [];
      $results['username'] = $username;
      $results['related ldap entry (before provisioning or syncing)'] = $user_ldap_entry;

      /** @var \Drupal\user\Entity\User $account */
      $existingAccount = user_load_by_name($username);
      if ($existingAccount) {
        $results['user entity (before provisioning or syncing)'] = $existingAccount->toArray();
        $results['User Authmap'] = ExternalAuthenticationHelper::getUserIdentifierFromMap($existingAccount->id());
      }
      else {
        $results['User Authmap'] = 'No authmaps available.  Authmaps only shown if user account exists beforehand';
      }

      $account = ['name' => $username];
      $sync_trigger_description = self::$sync_trigger_options[$selected_action];
      foreach ([LdapConfiguration::PROVISION_TO_DRUPAL, LdapConfiguration::PROVISION_TO_LDAP] as $direction) {
        if (LdapConfiguration::provisionEnabled($direction, $selected_action)) {
          if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL) {
            $processor->provisionDrupalAccount($account);
            $results['provisionDrupalAccount method results']["context = $sync_trigger_description"]['proposed'] = $account;
          }
          else {
            $provision_result = $ldapProcessor->provisionLdapEntry($username, NULL);
            $results['provisionLdapEntry method results']["context = $sync_trigger_description"] = $provision_result;
          }
        }
        else {
          if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL) {
            $results['provisionDrupalAccount method results']["context = $sync_trigger_description"] = 'Not enabled.';
          }
          else {
            $results['provisionLdapEntry method results']["context = $sync_trigger_description"] = 'Not enabled.';
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
