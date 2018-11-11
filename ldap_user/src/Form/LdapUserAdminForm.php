<?php

namespace Drupal\ldap_user\Form;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Link;
use Drupal\Core\Url;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\Mapping;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides the form to configure user configuration and field mapping.
 */
class LdapUserAdminForm extends ConfigFormBase implements LdapUserAttributesInterface, ContainerInjectionInterface {

  protected $cache;
  protected $moduleHandler;
  protected $entityTypeManager;

  protected $drupalAcctProvisionServerOptions;

  protected $ldapEntryProvisionServerOptions;

  /**
   * {@inheritdoc}
   */
  public function __construct(ConfigFactoryInterface $config_factory, CacheBackendInterface $cache, ModuleHandler $module_handler, EntityTypeManagerInterface $entity_type_manager) {
    parent::__construct($config_factory);

    $this->cache = $cache;
    $this->moduleHandler = $module_handler;
    $this->entityTypeManager = $entity_type_manager;

    $this->prepareBaseData();
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static (
      $container->get('config.factory'),
      $container->get('cache.default'),
      $container->get('module_handler'),
      $container->get('entity_type.manager')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_user_admin_form';
  }

  /**
   * {@inheritdoc}
   */
  public function getEditableConfigNames() {
    return ['ldap_user.settings'];
  }

  /**
   * Provisioning events from Drupal.
   *
   * @return array
   *   Available events.
   */
  private static function provisionsDrupalEvents() {
    return [
      self::EVENT_CREATE_DRUPAL_USER => t('On Drupal User Creation'),
      self::EVENT_SYNC_TO_DRUPAL_USER => t('On Sync to Drupal User'),
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('ldap_user.settings');

    if (count($this->drupalAcctProvisionServerOptions) == 0) {
      $url = Url::fromRoute('entity.ldap_server.collection');
      $edit_server_link = Link::fromTextAndUrl($this->t('@path', ['@path' => 'LDAP Servers']), $url)->toString();
      $message = $this->t('At least one LDAP server must configured and <em>enabled</em> before configuring LDAP user. Please go to @link to configure an LDAP server.',
        ['@link' => $edit_server_link]
      );
      $form['intro'] = [
        '#type' => 'item',
        '#markup' => $this->t('<h1>LDAP User Settings</h1>') . $message,
      ];
      return $form;
    }

    $form['intro'] = [
      '#type' => 'item',
      '#markup' => $this->t('<h1>LDAP User Settings</h1>'),
    ];

    $form['server_mapping_preamble'] = [
      '#type' => 'markup',
      '#markup' => $this->t('The relationship between a Drupal user and an LDAP entry is defined within the LDAP server configurations. The mappings below are for user fields, properties and data that are not automatically mapped elsewhere. <br>Read-only mappings are generally configured on the server configuration page and shown here as a convenience to you.'),
    ];

    $form['manual_drupal_account_editing'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Manual Drupal Account Creation'),
    ];

    $form['manual_drupal_account_editing']['manualAccountConflict'] = [
      '#type' => 'radios',
      '#options' => [
        self::MANUAL_ACCOUNT_CONFLICT_LDAP_ASSOCIATE => $this->t('Associate accounts, if available.'),
        self::MANUAL_ACCOUNT_CONFLICT_NO_LDAP_ASSOCIATE => $this->t('Do not associate accounts, allow conflicting accounts.'),
        self::MANUAL_ACCOUNT_CONFLICT_REJECT => $this->t('Do not associate accounts, reject conflicting accounts.'),
        self::MANUAL_ACCOUNT_CONFLICT_SHOW_OPTION_ON_FORM => $this->t('Show option on user create form to associate or not.'),
      ],
      '#title' => $this->t('How to resolve LDAP conflicts with manually created user accounts.'),
      '#description' => $this->t('This applies only to accounts created manually through admin/people/create for which an LDAP entry can be found on the LDAP server selected in "LDAP Servers Providing Provisioning Data"'),
      '#default_value' => $config->get('manualAccountConflict'),
    ];

    $form['basic_to_drupal'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Basic Provisioning to Drupal Account Settings'),
    ];

    $form['basic_to_drupal']['drupalAcctProvisionServer'] = [
      '#type' => 'radios',
      '#title' => $this->t('LDAP Servers Providing Provisioning Data'),
      '#required' => 1,
      '#default_value' => $config->get('drupalAcctProvisionServer') ? $config->get('drupalAcctProvisionServer') : 'none',
      '#options' => $this->drupalAcctProvisionServerOptions,
      '#description' => $this->t('Choose the LDAP server configuration to use in provisioning Drupal users and their user fields.'),
      '#states' => [
        // Action to take.
        'enabled' => [
          ':input[name=drupalAcctProvisionTriggers]' => ['value' => self::PROVISION_DRUPAL_USER_ON_USER_AUTHENTICATION],
        ],
      ],
    ];

    $form['basic_to_drupal']['drupalAcctProvisionTriggers'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Drupal Account Provisioning Events'),
      '#required' => FALSE,
      '#default_value' => $config->get('drupalAcctProvisionTriggers'),
      '#options' => [
        self::PROVISION_DRUPAL_USER_ON_USER_AUTHENTICATION => $this->t('Create or Sync to Drupal user on successful authentication with LDAP credentials. (Requires LDAP Authentication module).'),
        self::PROVISION_DRUPAL_USER_ON_USER_UPDATE_CREATE => $this->t('Create or Sync to Drupal user anytime a Drupal user account is created or updated. Requires a server with binding method of "Service Account Bind" or "Anonymous Bind".'),
      ],
      '#description' => $this->t('Which user fields and properties are synced on create or sync is determined in the "Provisioning from LDAP to Drupal mappings" table below in the right two columns.'),
    ];

    $form['basic_to_drupal']['userConflictResolve'] = [
      '#type' => 'radios',
      '#title' => $this->t('Existing Drupal User Account Conflict'),
      '#required' => 1,
      '#default_value' => $config->get('userConflictResolve'),
      '#options' => [
        self::USER_CONFLICT_LOG => $this->t("Don't associate Drupal account with LDAP. Require user to use Drupal password. Log the conflict"),
        self::USER_CONFLICT_ATTEMPT_RESOLVE => $this->t('Associate Drupal account with the LDAP entry. This option is useful for creating accounts and assigning roles before an LDAP user authenticates.'),
      ],
      '#description' => $this->t('What should be done if a local Drupal or other external user account already exists with the same login name.'),
    ];

    $form['basic_to_drupal']['acctCreation'] = [
      '#type' => 'radios',
      '#title' => $this->t('Application of Drupal Account settings to LDAP Authenticated Users'),
      '#required' => 1,
      '#default_value' => $config->get('acctCreation'),
      '#options' => [
        self::ACCOUNT_CREATION_LDAP_BEHAVIOUR => $this->t('Account creation settings at /admin/config/people/accounts/settings do not affect "LDAP Associated" Drupal accounts.'),
        self::ACCOUNT_CREATION_USER_SETTINGS_FOR_LDAP => $this->t('Account creation policy at /admin/config/people/accounts/settings applies to both Drupal and LDAP Authenticated users. "Visitors" option automatically creates and account when they successfully LDAP authenticate. "Admin" and "Admin with approval" do not allow user to authenticate until the account is approved.'),
      ],
    ];

    $form['basic_to_drupal']['disableAdminPasswordField'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Disable the password fields at /admin/create/people and generate a random password.'),
      '#default_value' => $config->get('disableAdminPasswordField'),
    ];

    $form['basic_to_drupal']['userUpdateMechanism'] = [
      '#type' => 'fieldset',
      '#title' => 'Periodic user update mechanism',
      '#description' => $this->t('Allows you to sync the result of an LDAP query with your users. Creates new users and updates existing ones.'),
    ];

    if ($this->moduleHandler->moduleExists('ldap_query')) {
      $updateMechanismOptions = ['none' => $this->t('Do not update')];

      $storage = $this->entityTypeManager->getStorage('ldap_query_entity');
      $ids = $storage
        ->getQuery()
        ->condition('status', 1)
        ->execute();
      $queries = $storage->loadMultiple($ids);
      foreach ($queries as $query) {
        $updateMechanismOptions[$query->id()] = $query->label();
      }
      $form['basic_to_drupal']['userUpdateMechanism']['userUpdateCronQuery'] = [
        '#type' => 'select',
        '#title' => $this->t('LDAP query containing the list of entries to update'),
        '#required' => FALSE,
        '#default_value' => $config->get('userUpdateCronQuery'),
        '#options' => $updateMechanismOptions,
      ];

      $form['basic_to_drupal']['userUpdateMechanism']['userUpdateCronInterval'] = [
        '#type' => 'select',
        '#title' => $this->t('How often should each user be synced?'),
        '#default_value' => $config->get('userUpdateCronInterval'),
        '#options' => [
          'always' => $this->t('On every cron run'),
          'daily' => $this->t('Daily'),
          'weekly' => $this->t('Weekly'),
          'monthly' => $this->t('Monthly'),
        ],
      ];
    }
    else {
      $form['basic_to_drupal']['userUpdateMechanism']['userUpdateCronQuery'] = [
        '#type' => 'value',
        '#value' => 'none',
      ];
      $form['basic_to_drupal']['userUpdateMechanism']['userUpdateCronInterval'] = [
        '#type' => 'value',
        '#value' => 'monthly',
      ];
      $form['basic_to_drupal']['userUpdateMechanism']['notice'] = [
        '#markup' => $this->t('Only available with LDAP Query enabled.'),
      ];
    }

    $form['basic_to_drupal']['orphanedAccounts'] = [
      '#type' => 'fieldset',
      '#title' => 'Periodic orphaned accounts update mechanism',
      '#description' => $this->t('<strong>Warning: Use this feature at your own risk!</strong>'),
    ];

    $form['basic_to_drupal']['orphanedAccounts']['orphanedCheckQty'] = [
      '#type' => 'textfield',
      '#size' => 10,
      '#title' => $this->t('Number of users to check each cron run.'),
      '#default_value' => $config->get('orphanedCheckQty'),
      '#required' => FALSE,
    ];

    $account_options = [];
    $account_options['ldap_user_orphan_do_not_check'] = $this->t('Do not check for orphaned Drupal accounts.');
    $account_options['ldap_user_orphan_email'] = $this->t('Perform no action, but email list of orphaned accounts. (All the other options will send email summaries also.)');
    foreach (user_cancel_methods()['#options'] as $option_name => $option_title) {
      $account_options[$option_name] = $option_title;
    }

    $form['basic_to_drupal']['orphanedAccounts']['orphanedDrupalAcctBehavior'] = [
      '#type' => 'radios',
      '#title' => $this->t('Action to perform on Drupal accounts that no longer have corresponding LDAP entries'),
      '#default_value' => $config->get('orphanedDrupalAcctBehavior'),
      '#options' => $account_options,
      '#description' => $this->t('It is highly recommended to fetch an email report first before attempting to disable or even delete users.'),
    ];

    $form['basic_to_drupal']['orphanedAccounts']['orphanedCheckQty'] = [
      '#type' => 'textfield',
      '#size' => 10,
      '#title' => $this->t('Number of users to check each cron run.'),
      '#default_value' => $config->get('orphanedCheckQty'),
      '#required' => FALSE,
    ];

    $form['basic_to_drupal']['orphanedAccounts']['orphanedAccountCheckInterval'] = [
      '#type' => 'select',
      '#title' => $this->t('How often should each user be checked again?'),
      '#default_value' => $config->get('orphanedAccountCheckInterval'),
      '#options' => [
        'always' => $this->t('On every cron run'),
        'daily' => $this->t('Daily'),
        'weekly' => $this->t('Weekly'),
        'monthly' => $this->t('Monthly'),
      ],
      '#required' => FALSE,
    ];

    $form['basic_to_ldap'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Basic Provisioning to LDAP Settings'),
    ];

    $form['basic_to_ldap']['ldapEntryProvisionServer'] = [
      '#type' => 'radios',
      '#title' => $this->t('LDAP Servers to Provision LDAP Entries on'),
      '#required' => 1,
      '#default_value' => $config->get('ldapEntryProvisionServer') ? $config->get('ldapEntryProvisionServer') : 'none',
      '#options' => $this->ldapEntryProvisionServerOptions,
      '#description' => $this->t('Check ONE LDAP server configuration to create LDAP entries on.'),
    ];

    $form['basic_to_ldap']['ldapEntryProvisionTriggers'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('LDAP Entry Provisioning Events'),
      '#required' => FALSE,
      '#default_value' => $config->get('ldapEntryProvisionTriggers'),
      '#options' => [
        self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE => $this->t('Create or Sync to LDAP entry when a Drupal account is created or updated. Only applied to accounts with a status of approved.'),
        self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION => $this->t('Create or Sync to LDAP entry when a user authenticates.'),
        self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE => $this->t('Delete LDAP entry when the corresponding Drupal Account is deleted.  This only applies when the LDAP entry was provisioned by Drupal by the LDAP User module.'),
        self::PROVISION_DRUPAL_USER_ON_USER_ON_MANUAL_CREATION => $this->t('Provide option on admin/people/create to create corresponding LDAP Entry.'),
      ],
      '#description' => $this->t('Which LDAP attributes are synced on create or sync is determined in the "Provisioning from Drupal to LDAP mappings" table below in the right two columns.'),
    ];

    $directions = [
      self::PROVISION_TO_DRUPAL,
      self::PROVISION_TO_LDAP,
    ];

    foreach ($directions as $direction) {

      if ($direction == self::PROVISION_TO_DRUPAL) {
        $parent_fieldset = 'basic_to_drupal';
        $description = $this->t('Provisioning from LDAP to Drupal Mappings:');
      }
      else {
        $parent_fieldset = 'basic_to_ldap';
        $description = $this->t('Provisioning from Drupal to LDAP Mappings:');
      }

      $mapping_id = 'mappings__' . $direction;
      $table_id = $mapping_id . '__table';

      $form[$parent_fieldset][$mapping_id] = [
        '#type' => 'fieldset',
        '#title' => $description,
        '#description' => $this->t('See also the <a href="@wiki_link">Drupal.org wiki page</a> for further information on using LDAP tokens.',
          ['@wiki_link' => 'http://drupal.org/node/1245736']),
      ];

      $form[$parent_fieldset][$mapping_id][$table_id] = [
        '#type' => 'table',
        '#header' => [
          $this->t('Label'),
          $this->t('Machine name'),
          $this->t('Weight'),
          $this->t('Operations'),
        ],
        '#attributes' => ['class' => ['mappings-table']],
      ];

      $headers = $this->getServerMappingHeader($direction);
      $form[$parent_fieldset][$mapping_id][$table_id]['#header'] = $headers['header'];
      // Add in the second header as the first row.
      $form[$parent_fieldset][$mapping_id][$table_id]['second-header'] = [
        '#attributes' => ['class' => 'header'],
      ];
      // Second header uses the same format as header.
      foreach ($headers['second_header'] as $cell) {
        $form[$parent_fieldset][$mapping_id][$table_id]['second-header'][] = [
          '#title' => $cell['data'],
          '#type' => 'item',
        ];
        if (isset($cell['class'])) {
          $form[$parent_fieldset][$mapping_id][$table_id]['second-header']['#attributes'] = ['class' => [$cell['class']]];
        }
        if (isset($cell['rowspan'])) {
          $form[$parent_fieldset][$mapping_id][$table_id]['second-header']['#rowspan'] = $cell['rowspan'];
        }
        if (isset($cell['colspan'])) {
          $form[$parent_fieldset][$mapping_id][$table_id]['second-header']['#colspan'] = $cell['colspan'];
        }
      }

      $mappings_to_add = $this->getServerMappingFields($direction);

      if ($mappings_to_add) {
        $form[$parent_fieldset][$mapping_id][$table_id] += $mappings_to_add;
      }

      $more_ldap_info = '<h3>' . $this->t('Password Tokens') . '</h3><ul>';
      $more_ldap_info .= '<li>' . $this->t('Pwd: Random -- Uses a random Drupal generated password') . '</li>';
      $more_ldap_info .= '<li>' . $this->t('Pwd: User or Random -- Uses password supplied on user forms. If none available uses random password.') . '</li></ul>';
      $more_ldap_info .= '<h3>' . $this->t('Password Concerns') . '</h3>';
      $more_ldap_info .= '<ul>';
      $more_ldap_info .= '<li>' . $this->t("Provisioning passwords to LDAP means passwords must meet the LDAP's password requirements.  Password Policy module can be used to add requirements.") . '</li>';
      $more_ldap_info .= '<li>' . $this->t('Some LDAPs require a user to reset their password if it has been changed  by someone other that user.  Consider this when provisioning LDAP passwords.') . '</li>';
      $more_ldap_info .= '</ul></p>';
      $more_ldap_info .= '<h3>' . $this->t('Source Drupal User Tokens and Corresponding Target LDAP Tokens') . '</h3>';

      $more_ldap_info .= $this->t('Examples in form: Source Drupal User token => Target LDAP Token (notes): <ul>
        <li>Source Drupal User token => Target LDAP Token</li>
        <li>cn=[property.name],ou=test,dc=ad,dc=mycollege,dc=edu => [dn] (example of token and constants)</li>
        <li>top => [objectclass:0] (example of constants mapped to multivalued attribute)</li>
        <li>person => [objectclass:1] (example of constants mapped to multivalued attribute)</li>
        <li>organizationalPerson => [objectclass:2] (example of constants mapped to multivalued attribute)</li>
        <li>user => [objectclass:3] (example of constants mapped to multivalued attribute)</li>
        <li>Drupal Provisioned LDAP Account => [description] (example of constant)</li>
        <li>[field.field_lname] => [sn]</li></ul>');

      // Add some password notes.
      if ($direction == self::PROVISION_TO_LDAP) {
        $form[$parent_fieldset]['additional_ldap_hints'] = [
          '#type' => 'details',
          '#title' => $this->t('Additional information'),
          '#collapsible' => TRUE,
          '#collapsed' => TRUE,
          'directions' => [
            '#markup' => $more_ldap_info,
          ],
        ];
      }
    }

    $inputs = [
      'acctCreation',
      'userConflictResolve',
      'drupalAcctProvisionTriggers',
      'mappings__' . self::PROVISION_TO_DRUPAL,
    ];
    foreach ($inputs as $inputName) {
      $form['basic_to_drupal'][$inputName]['#states']['invisible'] =
        [
          ':input[name=drupalAcctProvisionServer]' => ['value' => 'none'],
        ];
    }

    $form['basic_to_drupal']['orphanedAccounts']['#states']['invisible'] =
      [
        ':input[name=drupalAcctProvisionServer]' => ['value' => 'none'],
      ];

    $inputs = ['orphanedCheckQty', 'orphanedAccountCheckInterval'];
    foreach ($inputs as $inputName) {
      $form['basic_to_drupal']['orphanedAccounts'][$inputName]['#states']['invisible'] =
        [
          ':input[name=orphanedDrupalAcctBehavior]' => ['value' => 'ldap_user_orphan_do_not_check'],
        ];
    }

    $inputs = [
      'ldapEntryProvisionTriggers',
      'additional_ldap_hints',
      'mappings__' . self::PROVISION_TO_LDAP,
    ];
    foreach ($inputs as $inputName) {
      $form['basic_to_ldap'][$inputName]['#states']['invisible'] =
        [
          ':input[name=ldapEntryProvisionServer]' => ['value' => 'none'],
        ];
    }

    $form['actions']['#type'] = 'actions';
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => 'Save',
    ];

    $this->notifyMissingSyncServerCombination($config);

    return $form;

  }

  /**
   * Check if the user starts with an an invalid configuration.
   *
   * @param \Drupal\Core\Config\Config $config
   *   Config object.
   */
  private function notifyMissingSyncServerCombination(Config $config) {

    $hasDrupalAcctProvServers = $config->get('drupalAcctProvisionServer');
    $hasDrupalAcctProvSettingsOptions = (count(array_filter($config->get('drupalAcctProvisionTriggers'))) > 0);
    if (!$config->get('drupalAcctProvisionServer') && $hasDrupalAcctProvSettingsOptions) {
      drupal_set_message($this->t('No servers are enabled to provide provisioning to Drupal, but Drupal account provisioning options are selected.'), 'warning');
    }
    elseif ($hasDrupalAcctProvServers && !$hasDrupalAcctProvSettingsOptions) {
      drupal_set_message($this->t('Servers are enabled to provide provisioning to Drupal, but no Drupal account provisioning options are selected. This will result in no syncing happening.'), 'warning');
    }

    $has_ldap_prov_servers = $config->get('ldapEntryProvisionServer');
    $has_ldap_prov_settings_options = (count(array_filter($config->get('ldapEntryProvisionTriggers'))) > 0);
    if (!$has_ldap_prov_servers && $has_ldap_prov_settings_options) {
      drupal_set_message($this->t('No servers are enabled to provide provisioning to LDAP, but LDAP entry options are selected.'), 'warning');
    }
    if ($has_ldap_prov_servers && !$has_ldap_prov_settings_options) {
      drupal_set_message($this->t('Servers are enabled to provide provisioning to LDAP, but no LDAP entry options are selected. This will result in no syncing happening.'), 'warning');
    }
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();

    $drupalMapKey = 'mappings__' . self::PROVISION_TO_DRUPAL . '__table';
    $ldapMapKey = 'mappings__' . self::PROVISION_TO_LDAP . '__table';

    if ($values['drupalAcctProvisionServer'] != 'none') {
      foreach ($values[$drupalMapKey] as $key => $mapping) {
        if (isset($mapping['configured_mapping']) && $mapping['configured_mapping'] == 1) {
          // Check that the source is not empty for the selected field to sync
          // to Drupal.
          if (!empty($mapping['drupal_attr'])) {
            if (empty($mapping['ldap_attr'])) {
              $formElement = $form['basic_to_drupal']['mappings__' . self::PROVISION_TO_DRUPAL][$drupalMapKey][$key];
              $form_state->setError($formElement, $this->t('Missing LDAP attribute'));
            }
          }
        }
      }
    }

    if ($values['ldapEntryProvisionServer'] != 'none') {
      foreach ($values[$ldapMapKey] as $key => $mapping) {
        if (isset($mapping['configured_mapping']) && $mapping['configured_mapping'] == 1) {
          // Check that the token is not empty if a user token is in use.
          if (isset($mapping['drupal_attr']) && $mapping['drupal_attr'] == 'user_tokens') {
            if (isset($mapping['user_tokens']) && empty(trim($mapping['user_tokens']))) {
              $formElement = $form['basic_to_ldap']['mappings__' . self::PROVISION_TO_LDAP][$ldapMapKey][$key];
              $form_state->setError($formElement, $this->t('Missing user token.'));
            }
          }

          // Check that a target attribute is set.
          if ($mapping['drupal_attr'] !== '0') {
            if ($mapping['ldap_attr'] == NULL) {
              $formElement = $form['basic_to_ldap']['mappings__' . self::PROVISION_TO_LDAP][$ldapMapKey][$key];
              $form_state->setError($formElement, $this->t('Missing LDAP attribute'));
            }
          }
        }
      }
    }

    $processedLdapSyncMappings = $this->syncMappingsFromForm($form_state->getValues(), self::PROVISION_TO_LDAP);
    $processedDrupalSyncMappings = $this->syncMappingsFromForm($form_state->getValues(), self::PROVISION_TO_DRUPAL);

    // Set error for entire table if [dn] is missing.
    if ($values['ldapEntryProvisionServer'] != 'none' && !isset($processedLdapSyncMappings['dn'])) {
      $form_state->setErrorByName($ldapMapKey,
        $this->t('Mapping rows exist for provisioning to LDAP, but no LDAP attribute is targeted for [dn]. One row must map to [dn]. This row will have a user token like cn=[property.name],ou=users,dc=ldap,dc=mycompany,dc=com')
      );
    }

    // Make sure only one attribute column is present.
    foreach ($processedLdapSyncMappings as $key => $mapping) {
      $maps = [];
      ConversionHelper::extractTokenAttributes($maps, $mapping['ldap_attr']);
      if (count(array_keys($maps)) > 1) {
        // TODO: Move this check out of processed mappings to be able to set the
        // error by field.
        $form_state->setErrorByName($ldapMapKey,
          $this->t('When provisioning to LDAP, LDAP attribute column must be singular token such as [cn]. %ldap_attr is not. Do not use compound tokens such as "[displayName] [sn]" or literals such as "physics".',
            ['%ldap_attr' => $mapping['ldap_attr']]
          )
        );
      }
    }

    // Notify the user if no actual synchronization event is active for a field.
    $this->checkEmptyEvents($processedLdapSyncMappings);
    $this->checkEmptyEvents($processedDrupalSyncMappings);

    if (!$this->checkPuidForOrphans($values['orphanedDrupalAcctBehavior'], $values['drupalAcctProvisionServer'])) {
      $form_state->setErrorByName('orphanedDrupalAcctBehavior', $this->t('You do not have a persistent user ID set in your server.'));
    }

  }

  /**
   * Check PUID for orphan configuration.
   *
   * Avoids the easy mistake of forgetting PUID and not being able to clean
   * up users which are no longer available due to missing data.
   *
   * @param string $orphanCheck
   *   Whether orphans are checked.
   * @param string $serverId
   *   Which server is used for provisioning.
   *
   * @return bool
   *   If there is an incosistent state.
   */
  private function checkPuidForOrphans($orphanCheck, $serverId) {
    if ($orphanCheck != 'ldap_user_orphan_do_not_check') {
      /** @var \Drupal\ldap_servers\Entity\Server $server */
      $server = $this->entityTypeManager->getStorage('ldap_server')->load($serverId);
      if (empty($server->get('unique_persistent_attr'))) {
        return FALSE;
      }
    }
    return TRUE;
  }

  /**
   * Warn about fields without associated events.
   *
   * @param array $mappings
   *   Field mappings.
   */
  private function checkEmptyEvents(array $mappings) {
    foreach ($mappings as $key => $mapping) {
      if (empty($mapping['prov_events'])) {
        drupal_set_message($this->t('No synchronization events checked in %item. This field will not be synchronized until some are checked.',
          ['%item' => $key]
        ), 'warning');
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $drupalAcctProvisionServer = ($form_state->getValue('drupalAcctProvisionServer') == 'none') ? NULL : $form_state->getValue('drupalAcctProvisionServer');
    $ldapEntryProvisionServer = ($form_state->getValue('ldapEntryProvisionServer') == 'none') ? NULL : $form_state->getValue('ldapEntryProvisionServer');

    $processedSyncMappings[self::PROVISION_TO_DRUPAL] = $this->syncMappingsFromForm($form_state->getValues(), self::PROVISION_TO_DRUPAL);
    $processedSyncMappings[self::PROVISION_TO_LDAP] = $this->syncMappingsFromForm($form_state->getValues(), self::PROVISION_TO_LDAP);

    $this->config('ldap_user.settings')
      ->set('drupalAcctProvisionServer', $drupalAcctProvisionServer)
      ->set('ldapEntryProvisionServer', $ldapEntryProvisionServer)
      ->set('drupalAcctProvisionTriggers', $this->reduceTriggerList($form_state->getValue('drupalAcctProvisionTriggers')))
      ->set('ldapEntryProvisionTriggers', $this->reduceTriggerList($form_state->getValue('ldapEntryProvisionTriggers')))
      ->set('userUpdateCronQuery', $form_state->getValue('userUpdateCronQuery'))
      ->set('userUpdateCronInterval', $form_state->getValue('userUpdateCronInterval'))
      ->set('orphanedDrupalAcctBehavior', $form_state->getValue('orphanedDrupalAcctBehavior'))
      ->set('orphanedCheckQty', $form_state->getValue('orphanedCheckQty'))
      ->set('orphanedAccountCheckInterval', $form_state->getValue('orphanedAccountCheckInterval'))
      ->set('userConflictResolve', $form_state->getValue('userConflictResolve'))
      ->set('manualAccountConflict', $form_state->getValue('manualAccountConflict'))
      ->set('acctCreation', $form_state->getValue('acctCreation'))
      ->set('disableAdminPasswordField', $form_state->getValue('disableAdminPasswordField'))
      ->set('ldapUserSyncMappings', $processedSyncMappings)
      ->save();
    $form_state->getValues();

    $this->cache->invalidate('ldap_user_sync_mapping');
    drupal_set_message($this->t('User synchronization configuration updated.'));
  }

  /**
   * Migrated from ldap_user.theme.inc .
   */
  private function getServerMappingHeader($direction) {

    if ($direction == self::PROVISION_TO_DRUPAL) {
      $header = [
        [
          'data' => $this->t('Source LDAP tokens'),
          'rowspan' => 1,
          'colspan' => 2,
        ],
        [
          'data' => $this->t('Target Drupal attribute'),
          'rowspan' => 1,
        ],
        [
          'data' => $this->t('Synchronization event'),
          'colspan' => count($this->provisionsDrupalEvents()),
          'rowspan' => 1,
        ],

      ];

      $second_header = [
        [
          'data' => $this->t('Examples:<ul><li>[sn]</li><li>[mail:0]</li><li>[ou:last]</li><li>[sn], [givenName]</li></ul> Constants such as <em>17</em> or <em>imported</em> should not be enclosed in [].'),
          'header' => TRUE,
        ],
        [
          'data' => $this->t('Convert from binary'),
          'header' => TRUE,
        ],
        [
          'data' => '',
          'header' => TRUE,
        ],
      ];

      foreach ($this->provisionsDrupalEvents() as $col_name) {
        $second_header[] = [
          'data' => $col_name,
          'header' => TRUE,
          'class' => 'header-provisioning',
        ];
      }
    }
    // To ldap.
    else {
      $header = [
        [
          'data' => $this->t('Source Drupal user attribute'),
          'rowspan' => 1,
          'colspan' => 3,
        ],
        [
          'data' => $this->t('Target LDAP token'),
          'rowspan' => 1,
        ],
        [
          'data' => $this->t('Synchronization event'),
          'colspan' => count($this->provisionsLdapEvents()),
          'rowspan' => 1,
        ],
      ];

      $second_header = [
        [
          'data' => $this->t('Note: Select <em>user tokens</em> to use token field.'),
          'header' => TRUE,
        ],
        [
          'data' => $this->t('Source Drupal user tokens such as: <ul><li>[property.name]</li><li>[field.field_fname]</li><li>[field.field_lname]</li></ul> Constants such as <em>from_drupal</em> or <em>18</em> should not be enclosed in [].'),
          'header' => TRUE,
        ],
        [
          'data' => $this->t('Convert From binary'),
          'header' => TRUE,
        ],
        [
          'data' => $this->t('Use singular token format such as: <ul><li>[sn]</li><li>[givenName]</li></ul>'),
          'header' => TRUE,
        ],
      ];
      foreach ($this->provisionsLdapEvents() as $col_name) {
        $second_header[] = [
          'data' => $col_name,
          'header' => TRUE,
          'class' => 'header-provisioning',
        ];
      }
    }
    return ['header' => $header, 'second_header' => $second_header];
  }

  /**
   * Return the server mappings for the fields.
   *
   * @param string $direction
   *   The provisioning direction.
   *
   * @return array|bool
   *   Returns the mappings.
   *
   * @TODO: We could duplicate this function and remove the entire handling
   * of "direction" that way.
   */
  private function getServerMappingFields($direction) {
    if ($direction == self::PROVISION_TO_NONE) {
      return FALSE;
    }

    $rows = [];

    $text = ($direction == self::PROVISION_TO_DRUPAL) ? 'target' : 'source';
    $user_attribute_options = ['0' => $this->t('Select') . ' ' . $text];

    $available_mappings = $this->processSyncMappings();
    if (!empty($available_mappings[$direction])) {
      /**  @var \Drupal\ldap_servers\Mapping $mapping */
      foreach ($available_mappings[$direction] as $target_id => $mapping) {

        if (empty($mapping->getLabel())) {
          continue;
        }
        if ($mapping->isConfigurable()) {
          $user_attribute_options[$target_id] = $mapping->getLabel();
        }
      }
    }

    if ($direction != self::PROVISION_TO_DRUPAL) {
      $user_attribute_options['user_tokens'] = '-- user tokens --';
    }

    $index = 0;

    // This adds rows for read-only fields not saved to configuration.
    foreach ($available_mappings[$direction] as $target_id => $mapping) {
      if ($mapping->isEnabled() && $mapping->getConfigurationModule() == 'ldap_user' && !$mapping->isConfigurable()) {
        $rows[$index] = $this->getSyncFormRow($direction, $mapping, $user_attribute_options, $index . $this->sanitizeMachineName($mapping->getId()));
        $index++;
      }
    }

    // This adds rows for fields saved to configuration.
    $config = $this->config('ldap_user.settings');
    if (!empty($config->get('ldapUserSyncMappings')[$direction])) {
      foreach ($config->get('ldapUserSyncMappings')[$direction] as $key => $value) {
        $mapping = NULL;
        // Our available mappings are always keyed by the Drupal attribute.
        if (isset($value['drupal_attr'], $available_mappings[$direction][$value['drupal_attr']])) {
          $mapping = $available_mappings[$direction][$value['drupal_attr']];
          if ($mapping->isEnabled() && $mapping->getConfigurationModule() == 'ldap_user' && $mapping->isConfigurable()) {
            $rows[$index] = $this->getSyncFormRow($direction, $mapping, $user_attribute_options, 'row-' . $index);
            $index++;
          }
        }
      }
    }

    // Adds four empty rows for adding more mappings.
    for ($i = 0; $i < 4; $i++) {
      $empty_mapping = new Mapping(
        '',
        '',
        TRUE,
        FALSE,
        [],
        'ldap_user',
        'ldap_user'
      );
      $rows[$index] = $this->getSyncFormRow($direction, $empty_mapping, $user_attribute_options, 'custom-' . $i);
      $index++;
    }

    return $rows;
  }

  /**
   *
   */
  private function getSyncFormRow($direction, Mapping $mapping, array $userAttributeOptions, $rowId) {
    if ($direction == self::PROVISION_TO_DRUPAL) {
      return $this->getSyncFormRowToDrupal($mapping, $userAttributeOptions);
    }
    else {
      return $this->getSyncFormRowToLdap($mapping, $userAttributeOptions, $rowId);
    }
  }

  /**
   * Get mapping form row to LDAP user provisioning mapping admin form table.
   *
   * @param string $action
   *   Action is either add, update, or nonconfigurable.
   * @param array $mapping
   *   Is current setting for updates or nonconfigurable items.
   * @param array $userAttributeOptions
   *   Attributes of Drupal user target options.
   * @param int $rowId
   *   Is current row in table.
   *
   * @return array
   *   A single row
   */
  private function getSyncFormRowToDrupal(Mapping $mapping, array $userAttributeOptions) {
    $result = [];

    if ($mapping->isConfigurable()) {
      $result['ldap_attr'] = [
        '#type' => 'textfield',
        '#title' => 'LDAP attribute',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getLdapAttribute(),
        '#size' => 20,
        '#maxlength' => 255,
        '#attributes' => ['class' => ['ldap-attr']],
      ];
      $result['convert'] = [
        '#type' => 'checkbox',
        '#title' => 'Convert from binary',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->isBinary(),
        '#attributes' => ['class' => ['convert']],
      ];
      $result['drupal_attr'] = [
        '#type' => 'select',
        '#title' => 'User attribute',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getDrupalAttribute(),
        '#options' => $userAttributeOptions,
      ];
    }
    else {
      $result['ldap_attr'] = [
        '#type' => 'item',
        '#default_value' => $mapping->getLdapAttribute(),
        '#markup' => $mapping->getLdapAttribute(),
        '#attributes' => ['class' => ['source']],
      ];
      $result['convert'] = [
        '#type' => 'checkbox',
        '#title' => 'Convert from binary',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->isBinary(),
        '#disabled' => TRUE,
        '#attributes' => ['class' => ['convert']],
      ];
      $result['drupal_attr'] = [
        '#type' => 'item',
        '#markup' => $mapping->getLabel(),
      ];
    }

    foreach ($this->provisionsDrupalEvents() as $prov_event => $prov_event_name) {
      $result[$prov_event] = [
        '#type' => 'checkbox',
        '#title' => $prov_event,
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getProvisioningEvents() ? (int) (in_array($prov_event, $mapping->getProvisioningEvents())) : NULL,
        '#disabled' => !$mapping->isConfigurable(),
        '#attributes' => ['class' => ['sync-method']],
      ];
    }

    // This one causes the extra column.
    $result['configured_mapping'] = [
      '#type' => 'value',
      '#value' => $mapping->isConfigurable(),
    ];

    return $result;
  }

  /**
   * Get mapping form row to LDAP user provisioning mapping admin form table.
   *
   * @param string $action
   *   Action is either add, update, or nonconfigurable.
   * @param array $mapping
   *   Is current setting for updates or nonconfigurable items.
   * @param array $userAttributeOptions
   *   Attributes of Drupal user target options.
   * @param int $rowId
   *   Is current row in table.
   *
   * @return array
   *   A single row
   */
  private function getSyncFormRowToLdap(Mapping $mapping, array $userAttributeOptions, $rowId) {

    $result = [];
    $idPrefix = 'mappings__ldap__table';
    $user_attribute_input_id = $idPrefix . "[$rowId][user_attr]";

    if ($mapping->isConfigurable()) {
      $result['drupal_attr'] = [
        '#type' => 'select',
        '#title' => 'User attribute',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getDrupalAttribute(),
        '#options' => $userAttributeOptions,
      ];
      $result['user_tokens'] = [
        '#type' => 'textfield',
        '#title' => 'User tokens',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getUserTokens(),
        '#size' => 20,
        '#maxlength' => 255,
        '#attributes' => ['class' => ['tokens']],
        '#states' => [
          'visible' => [
            'select[name="' . $user_attribute_input_id . '"]' => ['value' => 'user_tokens'],
          ],
        ],
      ];

      $result['convert'] = [
        '#type' => 'checkbox',
        '#title' => 'Convert from binary',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->isBinary(),
        '#disabled' => FALSE,
        '#attributes' => ['class' => ['convert']],
      ];
      $result['ldap_attr'] = [
        '#type' => 'textfield',
        '#title' => 'LDAP attribute',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getLdapAttribute(),
        '#size' => 20,
        '#maxlength' => 255,
        '#attributes' => ['class' => ['ldap-attr']],
      ];
    }
    else {
      $result['drupal_attr'] = [
        '#type' => 'item',
        '#markup' => $mapping->getLabel(),
      ];
      $result['user_tokens'] = [];
      $result['convert'] = [
        '#type' => 'checkbox',
        '#title' => 'Convert from binary',
        '#title_display' => 'invisible',
        '#default_value' => $mapping->isBinary(),
        '#disabled' => TRUE,
        '#attributes' => ['class' => ['convert']],
      ];
      $result['ldap_attr'] = [
        '#type' => 'item',
        '#default_value' => $mapping->getLdapAttribute(),
        '#markup' => $mapping->getLdapAttribute(),
        '#attributes' => ['class' => ['source']],
      ];
    }

    foreach ($this->provisionsLdapEvents() as $prov_event => $prov_event_name) {
      $result[$prov_event] = [
        '#type' => 'checkbox',
        '#title' => $prov_event,
        '#title_display' => 'invisible',
        '#default_value' => $mapping->getProvisioningEvents() ? (int) (in_array($prov_event, $mapping->getProvisioningEvents())) : NULL,
        '#disabled' => !$mapping->isConfigurable(),
        '#attributes' => ['class' => ['sync-method']],
      ];
    }

    // This one causes the extra column.
    $result['configured_mapping'] = [
      '#type' => 'value',
      '#value' => $mapping->isConfigurable(),
    ];

    return $result;
  }

  /**
   * Returns a config compatible machine name.
   *
   * @param string $string
   *   Field name to process.
   *
   * @return string
   *   Returns safe string.
   */
  private function sanitizeMachineName($string) {
    // Replace dots
    // Replace square brackets.
    return str_replace(['.', '[', ']'], ['-', '', ''], $string);
  }

  /**
   * Extract sync mappings array from mapping table in admin form.
   *
   * @param array $values
   *   As $form_state['values'] from Drupal FormAPI.
   * @param string $direction
   *   Direction to sync to.
   *
   * @return array
   *   Returns the relevant mappings.
   */
  private function syncMappingsFromForm(array $values, $direction) {
    $mappings = [];
    foreach ($values as $field_name => $value) {
      if (in_array($field_name, ['mappings__drupal _table', 'mappings__ldap__table'])) {
        foreach ($value as $row_descriptor => $columns) {
          if ($row_descriptor == 'second-header') {
            continue;
          }

          $key = ($direction == self::PROVISION_TO_DRUPAL) ? $this->sanitizeMachineName($columns['drupal_attr']) : $this->sanitizeMachineName($columns['ldap_attr']);
          // Only save if its configurable and has an LDAP and Drupal attributes.
          // The others are optional.
          if (isset($columns['configured_mapping']) && $columns['configured_mapping'] && !empty($columns['drupal_attr']) && !empty($columns['ldap_attr'])) {
            $mappings[$key] = [
              'drupal_attr' => trim($columns['drupal_attr']),
              'ldap_attr' => trim($columns['ldap_attr']),
              'convert' => $columns['convert'],
              'user_tokens' => isset($columns['user_tokens']) ? $columns['user_tokens'] : '',
              'enabled' => TRUE,
            ];
            $syncEvents = ($direction == self::PROVISION_TO_DRUPAL) ? $this->provisionsDrupalEvents() : $this->provisionsLdapEvents();
            foreach ($syncEvents as $prov_event => $discard) {
              if (isset($columns[$prov_event]) && $columns[$prov_event]) {
                $mappings[$key]['prov_events'][] = $prov_event;
              }
            }
          }
        }
      }
    }
    return $mappings;
  }

  /**
   * Returns the two provisioning events.
   *
   * @return array
   *   Create and Sync event in display form.
   */
  private function provisionsLdapEvents() {
    return [
      self::EVENT_CREATE_LDAP_ENTRY => $this->t('On LDAP Entry Creation'),
      self::EVENT_SYNC_TO_LDAP_ENTRY => $this->t('On Sync to LDAP Entry'),
    ];
  }

  /**
   *
   */
  private function reduceTriggerList($values) {
    $result = [];
    foreach ($values as $value) {
      if ($value !== 0) {
        $result[] = $value;
      }
    }
    return $result;
  }

  /**
   * Load servers and set their default values.
   */
  private function prepareBaseData() {
    $storage = $this->entityTypeManager->getStorage('ldap_server');
    $ids = $storage
      ->getQuery()
      ->condition('status', 1)
      ->execute();
    foreach ($storage->loadMultiple($ids) as $sid => $server) {
      /** @var \Drupal\ldap_servers\Entity\Server $server */
      $enabled = ($server->get('status')) ? 'Enabled' : 'Disabled';
      $this->drupalAcctProvisionServerOptions[$sid] = $server->label() . ' (' . $server->get('address') . ') Status: ' . $enabled;
      $this->ldapEntryProvisionServerOptions[$sid] = $server->label() . ' (' . $server->get('address') . ') Status: ' . $enabled;
    }

    $this->drupalAcctProvisionServerOptions['none'] = $this->t('None');
    $this->ldapEntryProvisionServerOptions['none'] = $this->t('None');
  }

  /**
   * Derive synchronization mappings from configuration.
   *
   * @return array
   */
  private function processSyncMappings() {
    $config = $this->config('ldap_user.settings');
    $available_user_attributes = [];
    $directions = [
      self::PROVISION_TO_DRUPAL => $config->get('drupalAcctProvisionServer'),
      self::PROVISION_TO_LDAP => $config->get('ldapEntryProvisionServer'),
    ];

    foreach ($directions as $direction => $sid) {
      $available_user_attributes[$direction] = [];
      $ldap_server = FALSE;
      if ($sid) {
        try {
          // TODO: DI.
          $ldap_server = Server::load($sid);
        }
        catch (\Exception $e) {
          // TODO: DI.
          \Drupal::logger('ldap_user')->error('Missing server');
        }
      }

      $params = [
        'ldap_server' => $ldap_server,
        'direction' => $direction,
      ];

      // This function does not add any attributes by itself but allows modules
      // such as ldap_user to inject them through this hook.
      $this->moduleHandler->alter(
        'ldap_user_attributes',
        $available_user_attributes[$direction],
        $params
      );
    }
    return $available_user_attributes;
  }

}
