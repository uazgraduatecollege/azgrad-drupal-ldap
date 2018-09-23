<?php

namespace Drupal\ldap_user\Processor;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapUserManager;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Processor for LDAP provisioning.
 */
class LdapUserProcessor implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $logger;
  protected $config;
  protected $detailLog;
  protected $tokenProcessor;
  protected $syncMapper;
  protected $moduleHandler;
  protected $entityTypeManager;
  protected $ldapUserManager;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   * @param \Drupal\ldap_servers\Logger\LdapDetailLog $detail_log
   * @param \Drupal\ldap_servers\Processor\TokenProcessor $token_processor
   * @param \Drupal\ldap_user\Helper\SyncMappingHelper $sync_mapper
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   * @param \Drupal\Core\Entity\EntityTypeManager $entity_type_manager
   * @param \Drupal\ldap_servers\LdapUserManager $ldap_user_manager
   */
  public function __construct(
    LoggerChannelInterface $logger,
    ConfigFactory $config_factory,
    LdapDetailLog $detail_log,
    TokenProcessor $token_processor,
    SyncMappingHelper $sync_mapper,
    ModuleHandler $module_handler,
    EntityTypeManager $entity_type_manager,
    LdapUserManager $ldap_user_manager) {
    $this->logger = $logger;
    $this->config = $config_factory->get('ldap_user.settings');
    $this->detailLog = $detail_log;
    $this->tokenProcessor = $token_processor;
    $this->syncMapper = $sync_mapper;
    $this->moduleHandler = $module_handler;
    $this->entityTypeManager = $entity_type_manager;
    $this->ldapUserManager = $ldap_user_manager;
  }

  /**
   * Given a Drupal account, sync to related LDAP entry.
   *
   * @param \Drupal\user\Entity\User $account
   *   Drupal user object.
   *
   * @return array|bool
   *   Successful sync.
   *
   *   Verify that we need actually need those for a missing test case or remove.
   *
   *   fixme: Restructure this function to provide an Entry all the time.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   */
  public function syncToLdapEntry(User $account) {
    $result = FALSE;

    if ($this->config->get('ldapEntryProvisionServer')) {
      /** @var \Drupal\ldap_servers\Entity\Server $server */
      $server = $this->entityTypeManager
        ->getStorage('ldap_server')
        ->load($this->config->get('ldapEntryProvisionServer'));

      $params = [
        'direction' => self::PROVISION_TO_LDAP,
        'prov_events' => [self::EVENT_SYNC_TO_LDAP_ENTRY],
        'module' => 'ldap_user',
        'function' => 'syncToLdapEntry',
        'include_count' => FALSE,
      ];

      try {
        $proposedLdapEntry = $this->drupalUserToLdapEntry($account, $server, $params);
      }
      catch (\Exception $e) {
        $this->logger->error('Unable to prepare LDAP entry: %message', ['%message', $e->getMessage()]);
        return FALSE;
      }

      if (is_array($proposedLdapEntry) && isset($proposedLdapEntry['dn'])) {
        // This array represents attributes to be modified; not comprehensive
        // list of attributes.
        $attributes = [];
        foreach ($proposedLdapEntry as $attributeName => $attributeValues) {
          if ($attributeName != 'dn') {
            if (isset($attributeValues['count'])) {
              unset($attributeValues['count']);
            }
            if (count($attributeValues) == 1) {
              $attributes[$attributeName] = $attributeValues[0];
            }
            else {
              $attributes[$attributeName] = $attributeValues;
            }
          }
        }

        // Stick $proposedLdapEntry in $ldap_entries array for drupal_alter.
        $proposedDnLowerCase = mb_strtolower($proposedLdapEntry['dn']);
        $ldap_entries = [$proposedDnLowerCase => $attributes];
        $context = [
          'action' => 'update',
          'corresponding_drupal_data' => [$proposedDnLowerCase => $attributes],
          'corresponding_drupal_data_type' => 'user',
          'account' => $account,
        ];
        $this->moduleHandler->alter('ldap_entry_pre_provision', $ldap_entries, $server, $context);
        // Remove altered $proposedLdapEntry from $ldap_entries array.
        $attributes = $ldap_entries[$proposedDnLowerCase];

        $attributes = array_change_key_case($attributes);
        $entry = new Entry($proposedLdapEntry['dn']);
        // TODO: Verify multi-value attributes.
        foreach ($attributes as $key => $value) {
          $entry->setAttribute($key, [$value]);
        }
        $result = $server->modifyLdapEntry($entry);

        if ($result) {
          $this->moduleHandler
            ->invokeAll('ldap_entry_post_provision', [
              $ldap_entries,
              $server,
              $context,
            ]);
        }

      }
      // Failed to get acceptable proposed LDAP entry.
      else {
        $result = FALSE;
      }
    }

    $tokens = [
      '%dn' => isset($proposedLdapEntry['dn']) ? $proposedLdapEntry['dn'] : 'null',
      '%sid' => $this->config->get('ldapEntryProvisionServer'),
      '%username' => $account->getAccountName(),
      '%uid' => (!method_exists($account, 'id') || empty($account->id())) ? '' : $account->id(),
      '%action' => $result ? $this->t('synced') : $this->t('not synced'),
    ];

    \Drupal::logger('ldap_user')
      ->info('LDAP entry on server %sid %action dn=%dn for username=%username, uid=%uid', $tokens);

    return $result;

  }

  /**
   * Populate LDAP entry array for provisioning.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account.
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   *   LDAP server.
   * @param array $params
   *   Parameters with the following key values:
   *   'ldap_context' =>
   *   'module' => module calling function, e.g. 'ldap_user'
   *   'function' => function calling function, e.g. 'provisionLdapEntry'
   *   'include_count' => should 'count' array key be included
   *   'direction' => self::PROVISION_TO_LDAP || self::PROVISION_TO_DRUPAL.
   * @param array|null $ldap_user_entry
   *   The LDAP user entry.
   *
   * @return array
   *   Array of (ldap entry, $result) in LDAP extension array format.
   *   THIS IS NOT THE ACTUAL LDAP ENTRY.
   *
   * @throws \Drupal\ldap_user\Exception\LdapBadParamsException
   */
  public function drupalUserToLdapEntry(UserInterface $account, Server $ldap_server, array $params, $ldap_user_entry = NULL) {
    $provision = (isset($params['function']) && $params['function'] == 'provisionLdapEntry');
    if (!$ldap_user_entry) {
      $ldap_user_entry = [];
    }

    if (!is_object($account) || !is_object($ldap_server)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $include_count = (isset($params['include_count']) && $params['include_count']);

    $direction = isset($params['direction']) ? $params['direction'] : self::PROVISION_TO_ALL;
    $prov_events = empty($params['prov_events']) ? LdapConfiguration::getAllEvents() : $params['prov_events'];

    $mappings = $this->syncMapper->getSyncMappings($direction, $prov_events);
    // Loop over the mappings.
    foreach ($mappings as $field_key => $field_detail) {
      list($ldapAttributeName, $ordinal) = $this->extractTokenParts($field_key);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($ldap_user_entry && isset($ldap_user_entry[$ldapAttributeName]) && is_array($ldap_user_entry[$ldapAttributeName]) && isset($ldap_user_entry[$ldapAttributeName][$ordinal])) {
        // Don't override values passed in.
        continue;
      }

      $synced = $this->syncMapper->isSynced($field_key, $params['prov_events'], self::PROVISION_TO_LDAP);
      if ($synced) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = $this->tokenProcessor->tokenReplace($account, $token, 'user_account');

        // Deal with empty/unresolved password.
        if (substr($token, 0, 10) == '[password.' && (!$value || $value == $token)) {
          if (!$provision) {
            // Don't overwrite password on sync if no value provided.
            continue;
          }
        }

        if ($ldapAttributeName == 'dn' && $value) {
          $ldap_user_entry['dn'] = $value;
        }
        elseif ($value) {
          if (!isset($ldap_user_entry[$ldapAttributeName]) || !is_array($ldap_user_entry[$ldapAttributeName])) {
            $ldap_user_entry[$ldapAttributeName] = [];
          }
          $ldap_user_entry[$ldapAttributeName][$ordinal] = $value;
          if ($include_count) {
            $ldap_user_entry[$ldapAttributeName]['count'] = count($ldap_user_entry[$ldapAttributeName]);
          }
        }
      }
    }

    // Allow other modules to alter $ldap_user.
    $this->moduleHandler->alter('ldap_entry', $ldap_user_entry, $params);

    return $ldap_user_entry;
  }

  /**
   * Extract parts of token.
   *
   * @param string $token
   *   Token or token expression with singular token in it, eg. [dn],
   *   [dn;binary], [titles:0;binary] [cn]@mycompany.com.
   *
   * @return array
   *   Array triplet containing [<attr_name>, <ordinal>, <conversion>].
   */
  private function extractTokenParts($token) {
    $attributes = [];
    ConversionHelper::extractTokenAttributes($attributes, $token);
    if (is_array($attributes)) {
      $keys = array_keys($attributes);
      $attr_name = $keys[0];
      $attr_data = $attributes[$attr_name];
      $ordinals = array_keys($attr_data['values']);
      $ordinal = $ordinals[0];
      return [$attr_name, $ordinal];
    }
    else {
      return [NULL, NULL];
    }

  }

  /**
   * Provision an LDAP entry if none exists.
   *
   * If one exists do nothing, takes Drupal user as argument.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user.
   * @param array $ldap_user
   *   LDAP user as pre-populated LDAP entry. Usually not provided.
   *
   * @return bool
   *   Provisioning successful.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   * @throws \Drupal\Core\Entity\EntityStorageException
   */
  public function provisionLdapEntry(UserInterface $account, array $ldap_user = NULL) {

    if ($account->isAnonymous()) {
      $this->logger->notice('Cannot provision LDAP user unless corresponding Drupal account exists.');
      return FALSE;
    }

    if (!$this->config->get('ldapEntryProvisionServer')) {
      $this->logger->error('No provisioning server enabled');
      return FALSE;
    }

    /** @var \Drupal\ldap_servers\Entity\Server $ldapServer */
    $ldapServer = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('ldapEntryProvisionServer'));
    $params = [
      'direction' => self::PROVISION_TO_LDAP,
      'prov_events' => [self::EVENT_CREATE_LDAP_ENTRY],
      'module' => 'ldap_user',
      'function' => 'provisionLdapEntry',
      'include_count' => FALSE,
    ];

    try {
      $proposedLdapEntry = $this->drupalUserToLdapEntry($account, $ldapServer, $params, $ldap_user);
    }
    catch (\Exception $e) {
      $this->logger->error('User or server is missing during LDAP provisioning: %message', ['%message', $e->getMessage()]);
      return FALSE;
    }

    if ((is_array($proposedLdapEntry) && isset($proposedLdapEntry['dn']) && $proposedLdapEntry['dn'])) {
      $proposedDn = $proposedLdapEntry['dn'];
    }
    else {
      $proposedDn = NULL;
    }
    $proposedDnLowercase = mb_strtolower($proposedDn);
    $existingLdapEntry = ($proposedDn) ? $ldapServer->checkDnExistsIncludeData($proposedDn, ['objectclass']) : NULL;

    if (!$proposedDn) {
      $this->detailLog->log('Failed to derive dn and or mappings', [], 'ldap_user');
      return FALSE;
    }
    elseif ($existingLdapEntry) {
      $this->logger->warning(
        'LDAP cannot provision the LDAP entry because an account exists already for %username.',
        ['%username' => $account->getAccountName()]
      );
      return FALSE;
    }
    else {
      // Stick $proposedLdapEntry in $ldapEntries array for drupal_alter.
      $ldapEntries = [$proposedDnLowercase => $proposedLdapEntry];
      $context = [
        'action' => 'add',
        'corresponding_drupal_data' => [$proposedDnLowercase => $account],
        'corresponding_drupal_data_type' => 'user',
        'account' => $account,
      ];
      $this->moduleHandler->alter('ldap_entry_pre_provision', $ldapEntries, $ldapServer, $context);
      // Remove altered $proposedLdapEntry from $ldapEntries array.
      $proposedLdapEntry = new Entry($proposedDn, $ldapEntries[$proposedDnLowercase]);
      $this->ldapUserManager->setServerById($ldapServer->id());
      $ldapEntryCreated = $this->ldapUserManager->createUserEntry($proposedLdapEntry);
      $callbackParams = [$ldapEntries, $ldapServer, $context];
      if ($ldapEntryCreated) {
        $this->moduleHandler
          ->invokeAll('ldap_entry_post_provision', $callbackParams);

        // Need to store <sid>|<dn> in ldap_user_prov_entries field, which may
        // contain more than one.
        $ldap_user_prov_entry = $ldapServer->id() . '|' . $proposedLdapEntry['dn'];
        if (NULL !== $account->get('ldap_user_prov_entries')) {
          $account->set('ldap_user_prov_entries', []);
        }
        $ldapUserProvisioningEntryExists = FALSE;
        if ($account->get('ldap_user_prov_entries')->value) {
          foreach ($account->get('ldap_user_prov_entries')->value as $fieldValueInstance) {
            if ($fieldValueInstance == $ldap_user_prov_entry) {
              $ldapUserProvisioningEntryExists = TRUE;
            }
          }
        }
        if (!$ldapUserProvisioningEntryExists) {
          // @TODO Serialise?
          $prov_entries = $account->get('ldap_user_prov_entries')->value;
          $prov_entries[] = [
            'value' => $ldap_user_prov_entry,
            'format' => NULL,
            'save_value' => $ldap_user_prov_entry,
          ];
          $account->set('ldap_user_prov_entries', $prov_entries);
          $account->save();
        }

      }
      else {
        $this->logger->error('LDAP entry for @username cannot be created on @sid not created because of an error. Proposed DN: %dn)',
          [
            '%dn' => $proposedLdapEntry->getDn(),
            '@sid' => $ldapServer->id(),
            '@username' => @$account->getAccountName(),
          ]);
        return FALSE;
      }
    }

    $this->detailLog->log(
      'LDAP entry for @username on server @sid created for DN %dn.',
      [
        '%dn' => $proposedLdapEntry->getDn(),
        '@sid' => $ldapServer->id(),
        '@username' => @$account->getAccountName(),
      ],
      'ldap_user'
    );

    return TRUE;
  }

  /**
   * Delete a provisioned LDAP entry.
   *
   * Given a Drupal account, delete LDAP entry that was provisioned based on it
   * normally this will be 0 or 1 entry, but the ldap_user_prov_entries field
   * attached to the user entity track each LDAP entry provisioned.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user account.
   *
   * @return bool
   *   FALSE indicates failed or action not enabled in LDAP user configuration.
   */
  public function deleteProvisionedLdapEntries(UserInterface $account) {
    // Determine server that is associated with user.
    $result = FALSE;
    $entries = $account->get('ldap_user_prov_entries')->getValue();
    foreach ($entries as $entry) {
      $parts = explode('|', $entry['value']);
      if (count($parts) == 2) {
        list($sid, $dn) = $parts;
        if ($this->ldapUserManager->setServerById($sid) && $dn) {
          $result = $this->ldapUserManager->deleteLdapEntry($dn);
          $tokens = [
            '%sid' => $sid,
            '%dn' => $dn,
            '%username' => $account->getAccountName(),
            '%uid' => $account->id(),
          ];
          if ($result) {
            $this->logger->info('LDAP entry on server %sid deleted dn=%dn. username=%username, uid=%uid', $tokens);
          }
          else {
            $this->logger->error('LDAP entry on server %sid not deleted because error. username=%username, uid=%uid', $tokens);
          }
        }
        else {
          $result = FALSE;
        }
      }
    }
    return $result;
  }

  /**
   * Given a Drupal account, find the related LDAP entry.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user account.
   * @param string|null $prov_events
   *   Provisioning event.
   *
   * @return bool|array
   *   False or LDAP entry
   */
  public function getProvisionRelatedLdapEntry(UserInterface $account, $prov_events = NULL) {
    if (!$prov_events) {
      $prov_events = LdapConfiguration::getAllEvents();
    }
    $sid = $this->config->get('ldapEntryProvisionServer');
    if (!$sid) {
      return FALSE;
    }
    // $user_entity->ldap_user_prov_entries,.
    // TODO: DI.
    $ldap_server = Server::load($sid);
    $params = [
      'direction' => self::PROVISION_TO_LDAP,
      'prov_events' => $prov_events,
      'module' => 'ldap_user',
      'function' => 'getProvisionRelatedLdapEntry',
      'include_count' => FALSE,
    ];

    try {
      $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $params);
    }
    catch (\Exception $e) {
      $this->logger->error('Unable to prepare LDAP entry: %message', ['%message', $e->getMessage()]);
      return FALSE;
    }

    if (!(is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn']) && $proposed_ldap_entry['dn'])) {
      return FALSE;
    }

    $ldap_entry = $ldap_server->checkDnExistsIncludeData($proposed_ldap_entry['dn'], []);
    return $ldap_entry;
  }

}
