<?php

namespace Drupal\ldap_servers\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapTransformationTraits;
use Drupal\ldap_servers\ServerInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Defines the Server entity.
 *
 * @ConfigEntityType(
 *   id = "ldap_server",
 *   label = @Translation("LDAP Server"),
 *   handlers = {
 *     "list_builder" = "Drupal\ldap_servers\ServerListBuilder",
 *     "form" = {
 *       "add" = "Drupal\ldap_servers\Form\ServerForm",
 *       "edit" = "Drupal\ldap_servers\Form\ServerForm",
 *       "delete" = "Drupal\ldap_servers\Form\ServerDeleteForm",
 *       "test" = "Drupal\ldap_servers\Form\ServerTestForm",
 *       "enable_disable" = "Drupal\ldap_servers\Form\ServerEnableDisableForm"
 *     }
 *   },
 *   config_prefix = "server",
 *   admin_permission = "administer ldap",
 *   entity_keys = {
 *     "id" = "id",
 *     "label" = "label",
 *     "uuid" = "uuid"
 *   },
 *   links = {
 *     "edit-form" = "/admin/config/people/ldap/server/{server}/edit",
 *     "delete-form" = "/admin/config/people/ldap/server/{server}/delete",
 *     "collection" = "/admin/config/people/ldap/server"
 *   },
 *   config_export = {
 *    "id",
 *    "label",
 *    "uuid",
 *    "account_name_attr",
 *    "address",
 *    "basedn",
 *    "bind_method",
 *    "binddn",
 *    "bindpw",
 *    "followrefs",
 *    "grp_derive_from_dn_attr",
 *    "grp_derive_from_dn",
 *    "grp_memb_attr_match_user_attr",
 *    "grp_memb_attr",
 *    "grp_nested",
 *    "grp_object_cat",
 *    "grp_test_grp_dn_writeable",
 *    "grp_test_grp_dn",
 *    "grp_unused",
 *    "grp_user_memb_attr_exists",
 *    "grp_user_memb_attr",
 *    "mail_attr",
 *    "mail_template",
 *    "picture_attr",
 *    "port",
 *    "status",
 *    "testing_drupal_user_dn",
 *    "testing_drupal_username",
 *    "timeout",
 *    "tls",
 *    "unique_persistent_attr_binary",
 *    "unique_persistent_attr",
 *    "user_attr",
 *    "user_dn_expression",
 *    "weight",
 *   }
 * )
 */
class Server extends ConfigEntityBase implements ServerInterface {

  use LdapTransformationTraits;

  /**
   * Server machine name.
   *
   * @var string
   */
  protected $id;

  /**
   * Human readable name.
   *
   * @var string
   */
  protected $label;

  /**
   * LDAP Server connection.
   *
   * @var resource|false
   */
  protected $connection = FALSE;

  /**
   * Logger channel.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * LDAP Details logger.
   *
   * @var \Drupal\ldap_servers\Logger\LdapDetailLog
   */
  protected $detailLog;

  /**
   * Token processor.
   *
   * @var \Drupal\ldap_servers\Processor\TokenProcessor
   */
  protected $tokenProcessor;

  /**
   * Module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandler
   */
  protected $moduleHandler;

  /**
   * Constructor.
   *
   * @param array $values
   *   Values.
   * @param string $entity_type
   *   Entity Type.
   */
  public function __construct(array $values, $entity_type) {
    parent::__construct($values, $entity_type);
    $this->logger = \Drupal::logger('ldap_servers');
    $this->detailLog = \Drupal::service('ldap.detail_log');
    $this->tokenProcessor = \Drupal::service('ldap.token_processor');
    $this->moduleHandler = \Drupal::service('module_handler');
  }

  /**
   * Returns the formatted label of the bind method.
   *
   * @return string
   *   The formatted text for the current bind.
   */
  public function getFormattedBind() {
    switch ($this->get('bind_method')) {
      case 'service_account':
      default:
        $namedBind = $this->t('service account bind');
        break;

      case 'user':
        $namedBind = $this->t('user credentials bind');
        break;

      case 'anon':
        $namedBind = $this->t('anonymous bind (search), then user credentials');
        break;

      case 'anon_user':
        $namedBind = $this->t('anonymous bind');
        break;
    }
    return $namedBind;
  }

  /**
   * Fetch base DN.
   *
   * @return array
   *   All base DN.
   *
   * @TODO: Improve storage in database (should be a proper array).
   */
  public function getBaseDn() {
    if ($this->get('basedn')) {
      $base_dn = explode("\r\n", $this->get('basedn'));
    }
    else {
      $base_dn = [];
    }
    return $base_dn;
  }

  /**
   * Returns the username from the LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   The LDAP entry.
   *
   * @return string
   *   The user name.
   */
  public function deriveUsernameFromLdapResponse(Entry $ldap_entry) {
    $accountName = FALSE;

    if ($this->get('account_name_attr')) {
      if ($ldap_entry->hasAttribute($this->get('account_name_attr'))) {
        $accountName = $ldap_entry->getAttribute($this->get('account_name_attr'))[0];
      }
    }
    elseif ($this->get('user_attr')) {
      if ($ldap_entry->hasAttribute($this->get('user_attr'))) {
        $accountName = $ldap_entry->getAttribute($this->get('user_attr'))[0];
      }
    }

    return $accountName;
  }

  /**
   * Returns the user's email from the LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   The LDAP entry.
   *
   * @return string|bool
   *   The user's mail value or FALSE if none present.
   */
  public function deriveEmailFromLdapResponse(Entry $ldap_entry) {
    // Not using template.
    if ($this->get('mail_attr') && $ldap_entry->hasAttribute($this->get('mail_attr'))) {
      return $ldap_entry->getAttribute($this->get('mail_attr'))[0];
    }

    if ($this->get('mail_template')) {
      // Template is of form [cn]@illinois.edu.
      return $this->tokenProcessor->ldapEntryReplacementsForDrupalAccount($ldap_entry, $this->get('mail_template'));
    }

    return FALSE;
  }

  /**
   * Fetches the persistent UID from the LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $ldapEntry
   *   The LDAP entry.
   *
   * @return string|false
   *   The user's PUID or permanent user id (within ldap), converted from
   *   binary, if applicable.
   */
  public function derivePuidFromLdapResponse(Entry $ldapEntry) {
    if ($this->get('unique_persistent_attr') && $ldapEntry->hasAttribute($this->get('unique_persistent_attr'))) {
      $puid = $ldapEntry->getAttribute($this->get('unique_persistent_attr'))[0];
      if (($this->get('unique_persistent_attr_binary'))) {
        return ConversionHelper::binaryConversionToString($puid);
      }
      else {
        return $puid;
      }
    }
    else {
      return FALSE;
    }
  }

}
