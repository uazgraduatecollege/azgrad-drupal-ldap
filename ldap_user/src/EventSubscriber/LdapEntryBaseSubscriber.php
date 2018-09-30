<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\LdapUserManager;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Class ProvisionLdapEntryOnUserCreation.
 */
abstract class LdapEntryBaseSubscriber implements EventSubscriberInterface, LdapUserAttributesInterface {

  protected $config;
  protected $logger;
  protected $detailLog;
  protected $entityTypeManager;
  protected $moduleHandler;
  protected $ldapUserManager;
  protected $syncMappingHelper;
  protected $tokenProcessor;

  /**
   *
   */
  public function __construct(
    ConfigFactory $config_factory,
    LoggerChannelInterface $logger,
    LdapDetailLog $detail_log,
    EntityTypeManagerInterface $entity_type_manager,
    ModuleHandlerInterface $module_handler,
    LdapUserManager $ldap_user_manager,
    SyncMappingHelper $sync_mapping_helper,
    TokenProcessor $token_processor) {
    $this->config = $config_factory->get('ldap_user.settings');
    $this->logger = $logger;
    $this->detailLog = $detail_log;
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->ldapUserManager = $ldap_user_manager;
    $this->syncMappingHelper = $sync_mapping_helper;
    $this->tokenProcessor = $token_processor;
  }

  /**
   */
  protected function provisionsLdapEntriesFromDrupalUsers() {
    if ($this->config->get('ldapEntryProvisionServer') &&
      count(array_filter(array_values($this->config->get('ldapEntryProvisionTriggers')))) > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   *
   */
  protected function checkExistingLdapEntry(UserInterface $account) {
    $authmap = \Drupal::service('externalauth.authmap')->get($account->id(), 'ldap_user');
    if ($authmap) {
      $this->ldapUserManager->queryAllBaseDnLdapForUsername($authmap);
    }
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
   *   'function' => function calling function, e.g. 'provisionLdapEntry'
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
    if (!$ldap_user_entry) {
      $ldap_user_entry = [];
    }

    if (!is_object($account) || !is_object($ldap_server)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $direction = isset($params['direction']) ? $params['direction'] : self::PROVISION_TO_ALL;
    $prov_event = empty($params['prov_event']) ? self::EVENT_SYNC_TO_LDAP_ENTRY : $params['prov_event'];

    $mappings = $this->syncMappingHelper->getFieldsSyncedToLdap($prov_event);
    // Loop over the mappings.
    foreach ($mappings as $field_key => $field_detail) {
      list($ldapAttributeName, $ordinal) = $this->extractTokenParts($field_key);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($ldap_user_entry &&
        isset($ldap_user_entry[$ldapAttributeName]) &&
        is_array($ldap_user_entry[$ldapAttributeName]) &&
        isset($ldap_user_entry[$ldapAttributeName][$ordinal])) {
        // Don't override values passed in.
        continue;
      }

      $synced = $this->syncMappingHelper->isSyncedToLdap($field_key, $prov_event);
      if ($synced) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = $this->tokenProcessor->tokenReplace($account, $token, 'user_account');

        // Deal with empty/unresolved password.
        if (substr($token, 0, 10) == '[password.' && (!$value || $value == $token)) {
          // Don't overwrite password on sync if no value provided.
          continue;
        }

        if ($ldapAttributeName == 'dn' && $value) {
          $ldap_user_entry['dn'] = $value;
        }
        elseif ($value) {
          if (!isset($ldap_user_entry[$ldapAttributeName]) || !is_array($ldap_user_entry[$ldapAttributeName])) {
            $ldap_user_entry[$ldapAttributeName] = [];
          }
          $ldap_user_entry[$ldapAttributeName][$ordinal] = $value;
        }
      }
    }

    // Allow other modules to alter $ldap_user.
    $this->moduleHandler->alter('ldap_entry', $ldap_user_entry, $params);

    return $ldap_user_entry;
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
        'prov_event' => self::EVENT_SYNC_TO_LDAP_ENTRY,
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
          $params = [$ldap_entries, $server, $context];
          $this->moduleHandler->invokeAll('ldap_entry_post_provision', $params);
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
    $this->logger->info('LDAP entry on server %sid %action dn=%dn for username=%username, uid=%uid', $tokens);

    return $result;

  }

  /**
   *
   */
  protected function extractTokenParts($token) {
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

}
