<?php

namespace Drupal\ldap_servers\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapProtocolInterface;
use Drupal\ldap_servers\ServerInterface;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\user\Entity\User;
use Symfony\Component\Ldap\Adapter\ExtLdap\Collection;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\LdapException;

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
 *   }
 * )
 */
class Server extends ConfigEntityBase implements ServerInterface, LdapProtocolInterface {

  const LDAP_SERVER_LDAP_QUERY_CHUNK = 50;
  const LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT = 10;


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
   * @var \Drupal\ldap_servers\LdapBridge
   */
  protected $ldapBridge;

  /**
   * @var \Symfony\Component\Ldap\Ldap
   */
  protected $ldap;

  /**
   * Constructor.
   */
  public function __construct(array $values, $entity_type) {
    parent::__construct($values, $entity_type);
    $this->logger = \Drupal::logger('ldap_servers');
    $this->detailLog = \Drupal::service('ldap.detail_log');
    $this->tokenProcessor = \Drupal::service('ldap.token_processor');
    $this->moduleHandler = \Drupal::service('module_handler');
    // TODO: The bridge should not be needed here.
    // Functionality requiring it should be abstracted out of the Server entity.
    $this->ldapBridge = \Drupal::service('ldap_bridge');
    $this->ldapBridge->setServer($this);
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
        $namedBind = t('service account bind');
        break;

      case 'user':
        $namedBind = t('user credentials bind');
        break;

      case 'anon':
        $namedBind = t('anonymous bind (search), then user credentials');
        break;

      case 'anon_user':
        $namedBind = t('anonymous bind');
        break;
    }
    return $namedBind;
  }

  /**
   * Only required for status overview page.
   */
  public function bind() {
    if ($this->ldapBridge->bind()) {
      $this->ldap = $this->ldapBridge->get();
    }
  }

  /**
   * Checks if connected and connects and binds otherwise.
   */
  public function connectAndBindIfNotAlready() {
    if (!$this->ldap) {
      $this->bind();
    }
  }

  /**
   * Does dn exist for this server and what is its data?
   *
   * @param string $dn
   *   DN to search for.
   * @param array $attributes
   *   In same form as ldap_read $attributes parameter.
   *
   * @return bool|Entry
   *   Return ldap entry or false.
   */
  public function checkDnExistsIncludeData($dn, array $attributes) {
    $this->connectAndBindIfNotAlready();

    $options = [
      'filter' => $attributes,
      'scope' => 'base',
    ];

    try {
      $result = $this->ldap->query($dn, '(objectclass=*)', $options)->execute();
    }
    catch (LdapException $e) {
      return FALSE;
    }

    if ($result->count() > 0) {
      return $result->toArray()[0];
    }
    else {
      return FALSE;
    }
  }

  /**
   * Does dn exist for this server?
   *
   * @param string $dn
   *   DN to search for.
   *
   * @return bool
   *   DN exists.
   */
  public function checkDnExists($dn) {
    $this->connectAndBindIfNotAlready();

    $options = [
      'filter' => ['objectclass'],
      'scope' => 'base',
    ];

    try {
      $result = $this->ldap->query($dn, '(objectclass=*)', $options)->execute();
    }
    catch (LdapException $e) {
      return FALSE;
    }

    if ($result->count() > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Create LDAP entry.
   *
   * @param array $attributes
   *   Should follow the structure of ldap_add functions.
   *   Entry array: http://us.php.net/manual/en/function.ldap-add.php
   *    $attributes["attribute1"] = "value";
   *    $attributes["attribute2"][0] = "value1";
   *    $attributes["attribute2"][1] = "value2";.
   * @param string $dn
   *   Used as DN if $attributes['dn'] not present.
   *
   * @return bool
   *   Result of action.
   *
   *   TODO: Remove doc above or file bug upstream.
   *   TODO: Relies on one server attribute, consider moving into an
   *   EntryManagerAdapter (possibly a subclass of bridge or trait).
   */
  public function createLdapEntry(Entry $entry) {
    $this->connectAndBindIfNotAlready();

    // This is probably not necessary anymore.
    if ($entry->hasAttribute('dn')) {
      $entry->removeAttribute('dn');
    }

    if ($entry->hasAttribute('unicodePwd') && $this->get('type') == 'ad') {
      $entry->setAttribute('unicodePwd', [$this->convertPasswordForActiveDirectoryunicodePwd($entry->getAttribute('unicodePwd')[0])]);
    }

    try {
      $this->ldap->getEntryManager()->add($entry);
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP server %id exception: %ldap_error", [
        '%id' => $this->id(),
        '%ldap_error' => $e->getMessage(),
      ]
          );
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Perform an LDAP delete.
   *
   * @param string $dn
   *   DN of entry.
   *
   * @return bool
   *   Result of ldap_delete() call.
   */
  public function deleteLdapEntry($dn) {
    $this->connectAndBindIfNotAlready();

    try {
      $this->ldap->getEntryManager()->remove(new Entry($dn));
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP serrver deletion error on %id: %message", [
        '%message' => $e->getMessage(),
        '%id' => $this->id(),
      ]
          );
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Wrapper for ldap_escape().
   *
   * Helpful for unit testing without the PHP LDAP module.
   *
   * @param string $string
   *   String to escape.
   *
   * @return mixed|string
   *   Escaped string.
   */
  public static function ldapEscape($string) {
    if (function_exists('ldap_escape')) {
      return ldap_escape($string);
    }
    else {
      return str_replace(['*', '\\', '(', ')'], ['\\*', '\\\\', '\\(', '\\)'], $string);
    }
  }

  /**
   * Remove unchanged attributes from entry.
   *
   * Given 2 LDAP entries, old and new, removed unchanged values to avoid
   * security errors and incorrect date modified.
   *
   * @param array $newEntry
   *   LDAP entry in form <attribute> => <value>.
   * @param array $oldEntry
   *   LDAP entry in form <attribute> => ['count' => N, [<value>,...<value>]].
   *
   * @return array
   *   LDAP entry with no values that have NOT changed.
   */
  public static function removeUnchangedAttributes(array $newEntry, array $oldEntry) {
    foreach ($newEntry as $key => $newValue) {
      $oldValue = FALSE;
      $oldValueIsScalar = NULL;
      $keyLowercased = mb_strtolower($key);
      // TODO: Make this if loop include the actions when tests are available.
      if (isset($oldEntry[$keyLowercased])) {
        if ($oldEntry[$keyLowercased]['count'] == 1) {
          $oldValue = $oldEntry[$keyLowercased][0];
          $oldValueIsScalar = TRUE;
        }
        else {
          unset($oldEntry[$keyLowercased]['count']);
          $oldValue = $oldEntry[$keyLowercased];
          $oldValueIsScalar = FALSE;
        }
      }

      // Identical multivalued attributes.
      if (is_array($newValue) && is_array($oldValue) && count(array_diff($newValue, $oldValue)) == 0) {
        unset($newEntry[$key]);
      }
      elseif ($oldValueIsScalar && !is_array($newValue) && mb_strtolower($oldValue) == mb_strtolower($newValue)) {
        // Don't change values that aren't changing to avoid false permission
        // constraints.
        unset($newEntry[$key]);
      }
    }
    return $newEntry;
  }

  /**
   * Modify attributes of LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *
   * @return bool
   *   Result of query.
   *
   * @deprecated symfony/ldap refactoring needed.
   */
  public function modifyLdapEntry(Entry $entry) {
    $this->connectAndBindIfNotAlready();
    $error_message = FALSE;

    try {
      $current = $this->ldap->query($entry->getDn(), 'objectClass=*')->execute();
    }
    catch (LdapException $e) {
      $error_message = $e->getMessage();
    }

    if ($error_message || $current->count() != 0) {
      $this->logger->error("LDAP server read error on modify in %id: %message ", [
        '%message' => $error_message,
        '%id' => $this->id(),
      ]
      );
      return FALSE;
    }

    $current = $current->toArray()[0];

    if (!empty($attributes['unicodePwd']) && $this->get('type') == 'ad') {
      $attributes['unicodePwd'] = $this->convertPasswordForActiveDirectoryunicodePwd($attributes['unicodePwd']);
    }

    // TODO: Make sure the empty attributes sent are actually an array.
    // TODO: Make sure that count et al are gone.
    foreach ($entry->getAttributes() as $new_key => $new_value) {
      if ($current->getAttribute($new_key) == $new_value) {
        $entry->removeAttribute($new_key);
      }
    }

    if (count($entry->getAttributes()) > 0) {
      try {
        $this->ldap->getEntryManager()->update($entry);
      }
      catch (LdapException $e) {
        $this->logger->error("LDAP server error updating %dn on %id: %message", [
          '%dn' => $entry->getDn(),
          '%id' => $this->id(),
          '%message' => $e->getMessage(),
        ]
              );
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Perform an LDAP search on all base dns and aggregate into one result.
   *
   * @param string $filter
   *   The search filter, such as sAMAccountName=jbarclay. Attribute values
   *   (e.g. jbarclay) should be esacaped before calling.
   * @param array $attributes
   *   List of desired attributes. If omitted, we only return "dn".
   *
   * @return \Symfony\Component\Ldap\Entry[]
   *   An array of matching entries combined from all DN.
   */
  public function searchAllBaseDns($filter, array $attributes = []) {
    $this->connectAndBindIfNotAlready();
    $all_entries = [];
    $options = [
      'filter' => $attributes,
    ];

    foreach ($this->getBaseDn() as $base_dn) {
      $relative_filter = str_replace(',' . $base_dn, '', $filter);
      try {
        $ldap_response = $this->ldap->query($base_dn, $relative_filter, $options)->execute();
      }
      catch (LdapException $e) {
        $this->logger->critical('LDAP search error with %message', [
          '%message' => $e->getMessage(),
        ]);
        continue;
      }

      if ($ldap_response->count() > 0) {
        $all_entries = array_merge($all_entries, $ldap_response->toArray());
      }
    }

    return $all_entries;
  }

  /**
   * Fetch base DN.
   *
   * @return array
   *   All base DN.
   *
   *   TODO: Make this function unnecessary by providing a field configuration
   *   and UI to keep DN as a proper array.
   */
  public function getBaseDn() {
    $baseDn = $this->get('basedn');

    if (!is_array($baseDn) && is_scalar($baseDn)) {
      $baseDn = explode("\r\n", $baseDn);
    }
    return $baseDn;
  }

  /**
   * Fetches the user account based on the persistent UID.
   *
   * @param string $puid
   *   As returned from ldap_read or other LDAP function (can be binary).
   *
   * @return bool|User
   *   The updated user or error.
   */
  public function userAccountFromPuid($puid) {

    $query = \Drupal::entityQuery('user');
    $query
      ->condition('ldap_user_puid_sid', $this->id(), '=')
      ->condition('ldap_user_puid', $puid, '=')
      ->condition('ldap_user_puid_property', $this->get('unique_persistent_attr'), '=')
      ->accessCheck(FALSE);

    $result = $query->execute();

    if (!empty($result)) {
      if (count($result) == 1) {
        return User::load(array_values($result)[0]);
      }
      else {
        $uids = implode(',', $result);
        $this->logger->error('Multiple users (uids: %uids) with same puid (puid=%puid, sid=%sid, ldap_user_puid_property=%ldap_user_puid_property)', [
          '%uids' => $uids,
          '%puid' => $puid,
          '%id' => $this->id(),
          '%ldap_user_puid_property' => $this->get('unique_persistent_attr'),
        ]
        );
        return FALSE;
      }
    }
    else {
      return FALSE;
    }

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
  public function userUsernameFromLdapEntry(Entry $ldap_entry) {
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
  public function userEmailFromLdapEntry(Entry $ldap_entry) {

    // Not using template.
    if ($this->get('mail_attr') && $ldap_entry->hasAttribute($this->get('mail_attr'))) {
      if ($ldap_entry->hasAttribute($this->get('mail_attr'))) {
        return $ldap_entry->getAttribute($this->get('mail_attr'))[0];
      }
      else {
        return FALSE;
      }
    }
    // Template is of form [cn]@illinois.edu.
    elseif ($this->get('mail_template')) {
      // TODO: Refactor.
      return $this->tokenProcessor->tokenReplace($ldap_entry, $this->get('mail_template'), 'ldap_entry');
    }
    else {
      return FALSE;
    }
  }

  /**
   * Fetches the persistent UID from the LDAP entry.
   *
   * @param array $ldapEntry
   *   The LDAP entry.
   *
   * @return string
   *   The user's PUID or permanent user id (within ldap), converted from
   *   binary, if applicable.
   */
  public function userPuidFromLdapEntry(Entry $ldapEntry) {
    if ($this->get('unique_persistent_attr') && $ldapEntry->hasAttribute($this->get('unique_persistent_attr'))) {
      $puid = $ldapEntry->getAttribute($this->get('unique_persistent_attr'))[0];
      return ($this->get('unique_persistent_attr_binary')) ? ConversionHelper::binaryConversionToString($puid) : $puid;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Queries LDAP server for the user.
   *
   * @param string $drupal_username
   *   Drupal user name.
   *
   * @return \Symfony\Component\Ldap\Entry|false|null
   *
   *   Todo: This function does return data and check for validity of response,
   *   this makes responses difficult to parse and should be optimized.
   */
  public function matchUsernameToExistingLdapEntry($drupal_username) {

    $this->connectAndBindIfNotAlready();

    foreach ($this->getBaseDn() as $base_dn) {
      if (empty($base_dn)) {
        continue;
      }

      $query = '(' . $this->get('user_attr') . '=' . ConversionHelper::escapeFilterValue($drupal_username) . ')';

      try {
        $ldap_response = $this->ldap->query($base_dn, $query)->execute();
      }
      catch (LdapException $e) {
        // Must find exactly one user for authentication to work.
        $this->logger->error('LDAP server query error %message', [
          '%message' => $e->getMessage(),
        ]
              );
        return FALSE;
      }
      if ($ldap_response->count() == 0) {
        continue;
      }
      elseif ($ldap_response->count() != 1) {
        // Must find exactly one user for authentication to work.
        $this->logger->error('Error: %count users found with %filter under %base_dn.', [
          '%count' => $ldap_response->count(),
          '%filter' => $query,
          '%base_dn' => $base_dn,
        ]
                );
        continue;
      }

      $match = $ldap_response->toArray()[0];
      // TODO: Make this more elegant.
      foreach ($match->getAttributes() as $key => $value) {
        $match->removeAttribute($key);
        $match->setAttribute(mb_strtolower($key), $value);
      }

      // TODO: Remove this if we are sure no one needs it anymore.
      $match->setAttribute('ldap_server_id', [$this->id()]);

      if ($this->get('bind_method') == 'anon_user') {
        return $match;
      }

      // Filter out results with spaces added before or after, which are
      // considered OK by LDAP but are no good for us. Some setups have multiple
      // $nameAttribute per entry, so we loop through all possible options.
      foreach ($match->getAttribute($this->get('user_attr')) as $value) {
        if (mb_strtolower(trim($value)) == mb_strtolower($drupal_username)) {
          return $match;
        }
      }
    }
  }

  /**
   * Is a user a member of group?
   *
   * @param string $groupDn
   *   Group DN in mixed case.
   * @param string $username
   *   A Drupal username.
   *
   * @return bool
   *   Whether the user belongs to the group.
   */
  public function groupIsMember($groupDn, $username) {
    $groupDns = $this->groupMembershipsFromUser($username);
    // While list of group dns is going to be in correct mixed case, $group_dn
    // may not since it may be derived from user entered values so make sure
    // in_array() is case insensitive.
    $lowerCasedGroupDns = array_keys(array_change_key_case(array_flip($groupDns), CASE_LOWER));
    if (is_array($groupDns) && in_array(mb_strtolower($groupDn), $lowerCasedGroupDns)) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Recurse through all child groups and add members.
   *
   * @param array $group_dn_entries
   *   Entries of LDAP group entries that are starting point. Should include at
   *   least 1 entry and must include 'objectclass'.
   * @param array $all_member_dns
   *   All member DN as an array of all groups the user is a member of. Mixed
   *   case values.
   * @param array $tested_group_dns
   *   Tested group IDs as an array array of tested group dn, cn, uid, etc.
   *   Mixed case values. Whether these value are dn, cn, uid, etc depends on
   *   what attribute members, uniquemember, memberUid contains whatever
   *   attribute is in $this->$tested_group_ids to avoid redundant recursion.
   * @param int $level
   *   Current level of recursion.
   * @param int $max_levels
   *   Maximum number of recursion levels allowed.
   * @param bool|array $object_classes
   *   You can set the object class evaluated for recursion here, otherwise
   *   derived from group configuration.
   *
   * @return bool
   *   If operation was successful.
   */
  public function groupMembersRecursive(Entry $group_dn_entries, array &$all_member_dns, array $tested_group_dns, $level, $max_levels, $object_classes = FALSE) {

    if (!$this->groupGroupEntryMembershipsConfigured() || !is_array($group_dn_entries)) {
      return FALSE;
    }

    foreach ($group_dn_entries as $member_entry) {
      // 1.  Add entry itself if of the correct type to $all_member_dns.
      $object_class_match = (!$object_classes || (count(array_intersect(array_values($member_entry['objectclass']), $object_classes)) > 0));
      $object_is_group = in_array($this->get('grp_object_cat'), array_map('strtolower', array_values($member_entry['objectclass'])));
      // Add member.
      if ($object_class_match && !in_array($member_entry['dn'], $all_member_dns)) {
        $all_member_dns[] = $member_entry['dn'];
      }

      // 2. If its a group, keep recurse the group for descendants.
      if ($object_is_group && $level < $max_levels) {
        if ($this->get('grp_memb_attr_match_user_attr') == 'dn') {
          $group_id = $member_entry['dn'];
        }
        else {
          $group_id = $member_entry[$this->get('grp_memb_attr_match_user_attr')][0];
        }
        // 3. skip any groups that have already been tested.
        if (!in_array($group_id, $tested_group_dns)) {
          $tested_group_dns[] = $group_id;
          $member_ids = $member_entry[$this->get('grp_memb_attr')];

          if (count($member_ids)) {
            // Example 1: (|(cn=group1)(cn=group2))
            // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
            $query_for_child_members = '(|(' . implode(")(", $member_ids) . '))';
            // Add or on object classes, otherwise get all object classes.
            if ($object_classes && count($object_classes)) {
              $object_classes_ors = ['(objectClass=' . $this->get('grp_object_cat') . ')'];
              foreach ($object_classes as $object_class) {
                $object_classes_ors[] = '(objectClass=' . $object_class . ')';
              }
              $query_for_child_members = '&(|' . implode($object_classes_ors) . ')(' . $query_for_child_members . ')';
            }

            $return_attributes = [
              'objectclass',
              $this->get('grp_memb_attr'),
              $this->get('grp_memb_attr_match_user_attr'),
            ];
            $child_member_entries = $this->searchAllBaseDns($query_for_child_members, $return_attributes);
            if ($child_member_entries !== FALSE) {
              $this->groupMembersRecursive($child_member_entries, $all_member_dns, $tested_group_dns, $level + 1, $max_levels, $object_classes);
            }
          }
        }
      }
    }
  }

  /**
   * Get list of all groups that a user is a member of.
   *
   * If nesting is configured, the list will include all parent groups. For
   * example, if the user is a member of the "programmer" group and the
   * "programmer" group is a member of the "it" group, the user is a member of
   * both the "programmer" and the "it" group. If $nested is FALSE, the list
   * will only include groups which are directly assigned to the user.
   *
   * @param string $user
   *   A Drupal user entity.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   */
  public function groupMembershipsFromUser($username) {

    $group_dns = FALSE;
    $user_ldap_entry = $this->matchUsernameToExistingLdapEntry($username);
    if (!$user_ldap_entry || $this->get('grp_unused')) {
      return FALSE;
    }

    // Preferred method.
    if ($this->groupUserMembershipsFromAttributeConfigured()) {
      $group_dns = $this->groupUserMembershipsFromUserAttr($user_ldap_entry);
    }
    elseif ($this->groupGroupEntryMembershipsConfigured()) {
      $group_dns = $this->groupUserMembershipsFromEntry($user_ldap_entry);
    }
    return $group_dns;
  }

  /**
   * Get list of groups that a user is a member of using the memberOf attribute.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   A Drupal user entity, an LDAP entry array of a user  or a username.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   *
   * @see groupMembershipsFromUser()
   */
  public function groupUserMembershipsFromUserAttr(Entry $ldap_entry) {
    if (!$this->groupUserMembershipsFromAttributeConfigured()) {
      return FALSE;
    }

    $groupAttribute = $this->get('grp_user_memb_attr');

    if ($ldap_entry->hasAttribute($groupAttribute)) {
      return FALSE;
    }

    $allGroupDns = [];
    $level = 0;

    $membersGroupDns = $ldap_entry[$groupAttribute];
    if (isset($membersGroupDns['count'])) {
      unset($membersGroupDns['count']);
    }
    $orFilters = [];
    foreach ($membersGroupDns as $memberGroupDn) {
      $allGroupDns[] = $memberGroupDn;
      if ($this->get('grp_nested')) {
        if ($this->get('grp_memb_attr_match_user_attr') == 'dn') {
          $member_value = $memberGroupDn;
        }
        else {
          $member_value = $this->getFirstRdnValueFromDn($memberGroupDn, $this->get('grp_memb_attr_match_user_attr'));
        }
        $orFilters[] = $this->get('grp_memb_attr') . '=' . self::ldapEscape($member_value);
      }
    }

    if ($this->get('grp_nested') && count($orFilters)) {
      $allGroupDns = $this->getNestedGroupDnFilters($allGroupDns, $orFilters, $level);
    }

    return $allGroupDns;
  }

  /**
   * Get list of all groups that a user is a member of by querying groups.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   *
   * @see groupMembershipsFromUser()
   */
  public function groupUserMembershipsFromEntry(Entry $ldap_entry) {
    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }

    // MIXED CASE VALUES.
    $all_group_dns = [];
    // Array of dns already tested to avoid excess queries MIXED CASE VALUES.
    $tested_group_ids = [];
    $level = 0;

    if ($this->get('grp_memb_attr_match_user_attr') == 'dn') {
      $member_value = $ldap_entry->getDn();
    }
    else {
      $member_value = $ldap_entry->getAttribute($this->get('grp_memb_attr_match_user_attr'))[0];
    }

    $groupQuery = '(&(objectClass=' . $this->get('grp_object_cat') . ')(' . $this->get('grp_memb_attr') . "=$member_value))";

    $this->connectAndBindIfNotAlready();

    // Need to search on all basedns one at a time.
    foreach ($this->getBaseDn() as $baseDn) {
      // Only need dn, so empty array forces return of no attributes.
      // TODO: See if this syntax is correct and returns us valid DN with no attributes.
      try {
        $ldap_result = $this->ldap->query($baseDn, $groupQuery, ['filter' => []])->execute();
      }
      catch (LdapException $e) {
        $this->logger->critical('LDAP search error with %message', [
          '%message' => $e->getMessage(),
        ]);
        continue;
      }

      if ($ldap_result->count() > 0) {
        $maxLevels = $this->get('grp_nested') ? self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT : 0;
        $this->groupMembershipsFromEntryRecursive($ldap_result, $all_group_dns, $tested_group_ids, $level, $maxLevels);
      }
    }
    return $all_group_dns;
  }

  /**
   * Recurse through all groups, adding parent groups to $all_group_dns array.
   *
   * @param array $current_group_entries
   *   Entries of LDAP groups, which are that are starting point. Should include
   *   at least one entry.
   * @param array $all_group_dns
   *   An array of all groups the user is a member of in mixed-case.
   * @param array $tested_group_ids
   *   An array of tested group DN, CN, UID, etc. in mixed-case. Whether these
   *   value are DN, CN, UID, etc. depends on what attribute members,
   *   uniquemember, or memberUid contains whatever attribute in
   *   $this->$tested_group_ids to avoid redundant recursion.
   * @param int $level
   *   Levels of recursion.
   * @param int $max_levels
   *   Maximum levels of recursion allowed.
   *
   * @return bool
   *   False for error or misconfiguration, otherwise TRUE. Results are passed
   *   by reference.
   *
   * @TODO: See if we can do this with groupAllMembers().
   */
  private function groupMembershipsFromEntryRecursive(Collection $current_group_entries, array &$all_group_dns, array &$tested_group_ids, $level, $max_levels) {

    if (!$this->groupGroupEntryMembershipsConfigured() || $current_group_entries->count() == 0) {
      return FALSE;
    }

    $or_filters = [];
    /** @var \Symfony\Component\Ldap\Entry $group_entry */
    foreach ($current_group_entries->toArray() as $key => $group_entry) {
      if ($this->get('grp_memb_attr_match_user_attr') == 'dn') {
        $member_id = $group_entry->getDn();
      }
      // Maybe cn, uid, etc is held.
      else {
        $member_id = $this->getFirstRdnValueFromDn($group_entry->getDn(), $this->get('grp_memb_attr_match_user_attr'));
      }

      if ($member_id && !in_array($member_id, $tested_group_ids)) {
        $tested_group_ids[] = $member_id;
        $all_group_dns[] = $group_entry->getDn();
        // Add $group_id (dn, cn, uid) to query.
        $or_filters[] = $this->get('grp_memb_attr') . '=' . self::ldapEscape($member_id);
      }
    }

    if (count($or_filters)) {
      // Only 50 or so per query.
      // TODO: We can likely remove this since we are fetching one result at a
      // time with symfony/ldap.
      for ($key = 0; $key < count($or_filters); $key = $key + self::LDAP_SERVER_LDAP_QUERY_CHUNK) {
        $current_or_filters = array_slice($or_filters, $key, self::LDAP_SERVER_LDAP_QUERY_CHUNK);
        // Example 1: (|(cn=group1)(cn=group2))
        // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
        $or = '(|(' . implode(")(", $current_or_filters) . '))';
        $query_for_parent_groups = '(&(objectClass=' . $this->get('grp_object_cat') . ')' . $or . ')';

        // Need to search on all base DNs one at a time.
        foreach ($this->getBaseDn() as $base_dn) {
          // No attributes, just dns needed.
          try {
            $ldap_result = $this->ldap->query($base_dn, $query_for_parent_groups, ['filter' => []])->execute();
          }
          catch (LdapException $e) {
            $this->logger->critical('LDAP search error with %message', [
              '%message' => $e->getMessage(),
            ]);
            continue;
          }

          if ($ldap_result->count() > 0 && $level < $max_levels) {
            // @TODO: Verify recursion with true return.
            $this->groupMembershipsFromEntryRecursive($ldap_result, $all_group_dns, $tested_group_ids, $level + 1, $max_levels);
          }
        }
      }
    }
    return TRUE;
  }

  /**
   * Get "groups" from derived from DN.
   *
   * Has limited usefulness.
   *
   * @param string $user
   *   A username.
   *
   * @return array|bool
   *   Array of group strings.
   */
  public function groupUserMembershipsFromDn($username) {

    if (!$this->get('grp_derive_from_dn') || !$this->get('grp_derive_from_dn_attr')) {
      return FALSE;
    }
    elseif ($ldap_entry = $this->matchUsernameToExistingLdapEntry($username)) {
      return $this->getAllRdnValuesFromDn($ldap_entry->getDn(), $this->get('grp_derive_from_dn_attr'));
    }
    else {
      return FALSE;
    }

  }

  /**
   * Check if group memberships from attribute are configured.
   *
   * @return bool
   *   Whether group user memberships are configured.
   */
  public function groupUserMembershipsFromAttributeConfigured() {
    return $this->get('grp_user_memb_attr_exists') && $this->get('grp_user_memb_attr');
  }

  /**
   * Check if group memberships from group entry are configured.
   *
   * @return bool
   *   Whether group memberships from group entry are configured.
   */
  public function groupGroupEntryMembershipsConfigured() {
    return $this->get('grp_memb_attr_match_user_attr') && $this->get('grp_memb_attr');
  }

  /**
   * Return the first RDN Value from DN.
   *
   * Given a DN (such as cn=jdoe,ou=people) and an RDN (such as cn),
   * determine that RND value (such as jdoe).
   *
   * @param string $dn
   *   Input DN.
   * @param string $rdn
   *   RDN Value to find.
   *
   * @return string
   *   Value of RDN.
   */
  private function getFirstRdnValueFromDn($dn, $rdn) {
    // Escapes attribute values, need to be unescaped later.
    $pairs = $this->ldapExplodeDn($dn, 0);
    array_shift($pairs);
    $rdn = mb_strtolower($rdn);
    $rdn_value = FALSE;
    foreach ($pairs as $p) {
      $pair = explode('=', $p);
      if (mb_strtolower(trim($pair[0])) == $rdn) {
        $rdn_value = ConversionHelper::unescapeDnValue(trim($pair[1]));
        break;
      }
    }
    return $rdn_value;
  }

  /**
   * Returns all RDN values from DN.
   *
   * Given a DN (such as cn=jdoe,ou=people) and an rdn (such as cn),
   * determine that RDN value (such as jdoe).
   *
   * @param string $dn
   *   Input DN.
   * @param string $rdn
   *   RDN Value to find.
   *
   * @return array
   *   All values of RDN.
   */
  private function getAllRdnValuesFromDn($dn, $rdn) {
    // Escapes attribute values, need to be unescaped later.
    $pairs = $this->ldapExplodeDn($dn, 0);
    array_shift($pairs);
    $rdn = mb_strtolower($rdn);
    $rdn_values = [];
    foreach ($pairs as $p) {
      $pair = explode('=', $p);
      if (mb_strtolower(trim($pair[0])) == $rdn) {
        $rdn_values[] = ConversionHelper::unescapeDnValue(trim($pair[1]));
        break;
      }
    }
    return $rdn_values;
  }

  /**
   * Wrapper for ldap_explode_dn().
   *
   * Helpful for unit testing without the PHP LDAP module.
   *
   * @param string $dn
   *   DN to explode.
   * @param int $attribute
   *   Attribute.
   *
   * @return array
   *   Exploded DN.
   */
  public static function ldapExplodeDn($dn, $attribute) {
    return ldap_explode_dn($dn, $attribute);
  }

  /**
   * Convert password to format required by Active Directory.
   *
   * For the purpose of changing or setting the password. Note that AD needs the
   * field to be called unicodePwd (as opposed to userPassword).
   *
   * @param string $password
   *   The password that is being formatted for Active Directory unicodePwd
   *   field.
   *
   * @return string
   *   $password surrounded with quotes and in UTF-16LE encoding
   */
  public function convertPasswordForActiveDirectoryunicodePwd($password) {
    // This function can be called with $attributes['unicodePwd'] as an array.
    if (!is_array($password)) {
      return mb_convert_encoding("\"{$password}\"", "UTF-16LE");
    }
    else {
      // Presumably there is no use case for there being more than one password
      // in the $attributes array, hence it will be at index 0 and we return in
      // kind.
      return [mb_convert_encoding("\"{$password[0]}\"", "UTF-16LE")];
    }
  }

  /**
   * Search within the nested groups for further filters.
   *
   * @param array $all_group_dns
   *   Currently set groups.
   * @param array $or_filters
   *   Filters before diving deeper.
   * @param int $level
   *   Last relevant nesting level.
   *
   * @return array
   *   Nested group filters.
   */
  private function getNestedGroupDnFilters(array $all_group_dns, array $or_filters, $level) {
    // Only 50 or so per query.
    for ($key = 0; $key < count($or_filters); $key = $key + self::LDAP_SERVER_LDAP_QUERY_CHUNK) {
      $current_or_filters = array_slice($or_filters, $key, self::LDAP_SERVER_LDAP_QUERY_CHUNK);
      // Example 1: (|(cn=group1)(cn=group2))
      // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
      $orFilter = '(|(' . implode(")(", $current_or_filters) . '))';
      $query_for_parent_groups = '(&(objectClass=' . $this->get('grp_object_cat') . ')' . $orFilter . ')';

      $this->connectAndBindIfNotAlready();
      // Need to search on all base DN one at a time.
      foreach ($this->getBaseDn() as $base_dn) {
        // No attributes, just dns needed.
        try {
          $ldap_result = $this->ldap->query($base_dn, $query_for_parent_groups, ['filter' => []])->execute();
        }
        catch (LdapException $e) {
          $this->logger->critical('LDAP search error with %message', [
            '%message' => $e->getMessage(),
          ]);
          continue;
        }
        if ($ldap_result->count() > 0 && $level < self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT) {
          $tested_group_ids = [];
          $this->groupMembershipsFromEntryRecursive($ldap_result, $all_group_dns, $tested_group_ids, $level + 1, self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT);
        }
      }
    }
    return $all_group_dns;
  }

  /**
   * Add a group entry.
   *
   * Functionality is not in use, only called by server test form.
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
   */
  public function groupAddGroup($group_dn, array $attributes = []) {

    if ($this->checkDnExists($group_dn)) {
      return FALSE;
    }

    $attributes = array_change_key_case($attributes, CASE_LOWER);
    if (empty($attributes['objectclass'])) {
      $objectClass = $this->get('grp_object_cat');
    }
    else {
      $objectClass = $attributes['objectclass'];
    }
    $attributes['objectclass'] = $objectClass;

    $context = [
      'action' => 'add',
      'corresponding_drupal_data' => [$group_dn => $attributes],
      'corresponding_drupal_data_type' => 'group',
    ];
    $ldap_entries = [$group_dn => $attributes];
    $this->moduleHandler->alter('ldap_entry_pre_provision', $ldap_entries, $this, $context);
    $attributes = $ldap_entries[$group_dn];

    $entry = new Entry($group_dn, $attributes);
    $ldap_entry_created = $this->createLdapEntry($entry);

    if ($ldap_entry_created) {
      $this->moduleHandler->invokeAll('ldap_entry_post_provision', [
        $ldap_entries,
        $this,
        $context,
      ]
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
   * Functionality is not in use, only called by server test form.
   *
   * @param string $group_dn
   *   Group DN as LDAP dn.
   * @param bool $only_if_group_empty
   *   TRUE = group should not be removed if not empty
   *   FALSE = groups should be deleted regardless of members.
   *
   * @return bool
   *   Removal result.
   */
  public function groupRemoveGroup($group_dn, $only_if_group_empty = TRUE) {

    if ($only_if_group_empty) {
      $members = $this->groupAllMembers($group_dn);
      if (is_array($members) && count($members) > 0) {
        return FALSE;
      }
    }
    return $this->deleteLdapEntry($group_dn);

  }

  /**
   * Add a member to a group.
   *
   * Functionality only called by server test form.
   *
   * @param string $group_dn
   *   LDAP group DN.
   * @param string $user
   *   LDAP user DN.
   *
   * @return bool
   *   Operation successful.
   *
   * @deprecated symfony/ldap refactoring needed.
   */
  public function groupAddMember($group_dn, $user) {
    $result = FALSE;
    if ($this->groupGroupEntryMembershipsConfigured()) {
      $this->connectAndBindIfNotAlready();
      $new_member = [$this->get('grp_memb_attr') => $user];
      $result = @ldap_mod_add($this->connection, $group_dn, $new_member);
    }

    return $result;
  }

  /**
   * Remove a member from a group.
   *
   * Functionality only called by server test form.
   *
   * @param string $group_dn
   *   LDAP DN group.
   * @param string $member
   *   LDAP DN member.
   *
   * @return bool
   *   Operation successful.
   *
   * @deprecated symfony/ldap refactoring needed.
   */
  public function groupRemoveMember($group_dn, $member) {
    $result = FALSE;
    if ($this->groupGroupEntryMembershipsConfigured()) {
      $del = [];
      $del[$this->get('grp_memb_attr')] = $member;
      $this->connectAndBindIfNotAlready();
      $result = @ldap_mod_del($this->connection, $group_dn, $del);
    }
    return $result;
  }

  /**
   * Get all members of a group.
   *
   * Currently not in use.
   *
   * @param string $group_dn
   *   Group DN as LDAP DN.
   *
   * @return bool|array
   *   FALSE on error, otherwise array of group members (could be users or
   *   groups).
   *
   * @TODO: Split return functionality or throw an error.
   */
  public function groupAllMembers($group_dn) {

    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }

    $attributes = [$this->get('grp_memb_attr'), 'cn', 'objectclass'];
    $group_entry = $this->checkDnExistsIncludeData($group_dn, $attributes);
    if (!$group_entry) {
      return FALSE;
    }
    else {
      // If attributes weren't returned, don't give false  empty group.
      if (empty($group_entry->getAttribute('cn'))) {
        return FALSE;
      }
      if (empty($group_entry->getAttribute($this->get('grp_memb_attr')))) {
        // If no attribute returned, no members.
        return [];
      }
      $members = $group_entry->getAttribute($this->get('grp_memb_attr'));

      $result = $this->groupMembersRecursive($group_entry, $members, [], 0, self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT);
      // Remove the DN of the source group.
      if (($key = array_search($group_dn, $members)) !== FALSE) {
        unset($members[$key]);
      }
    }

    if ($result !== FALSE) {
      return $members;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Get direct members of a group.
   *
   * Currently not in use.
   *
   * @param string $group_dn
   *   Group DN as LDAP DN.
   *
   * @return bool|array
   *   FALSE on error, otherwise array of group members (could be users or
   *   groups).
   *
   * @TODO: Split return functionality or throw an error.
   */
  public function groupMembers($group_dn) {

    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }

    $attributes = [$this->get('grp_memb_attr'), 'cn', 'objectclass'];
    $group_entry = $this->checkDnExistsIncludeData($group_dn, $attributes);
    if (!$group_entry) {
      return FALSE;
    }
    else {
      // If attributes weren't returned, don't give false, give empty group.
      if (!$group_entry->hasAttribute('cn')) {
        return FALSE;
      }
      if (!$group_entry->hasAttribute($this->get('grp_memb_attr'))) {
        // If no attribute returned, no members.
        return [];
      }
      else {
        return $group_entry->getAttribute($this->get('grp_memb_attr'));
      }
    }
  }

}
