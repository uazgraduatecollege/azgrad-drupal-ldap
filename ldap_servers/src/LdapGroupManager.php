<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Extension\ModuleHandler;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Symfony\Component\Ldap\Adapter\ExtLdap\Collection;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * LDAP Group Manager.
 */
class LdapGroupManager extends LdapBaseManager {

  use LdapTransformationTraits;

  const LDAP_QUERY_CHUNK = 50;
  const LDAP_QUERY_RECURSION_LIMIT = 10;

  /**
   * Check if group memberships from attribute are configured.
   *
   * @return bool
   *   Whether group user memberships are configured.
   */
  public function groupUserMembershipsFromAttributeConfigured() {
    return $this->server->get('grp_user_memb_attr_exists') && $this->server->get('grp_user_memb_attr');
  }

  /**
   * Check if group memberships from group entry are configured.
   *
   * @return bool
   *   Whether group memberships from group entry are configured.
   */
  public function groupGroupEntryMembershipsConfigured() {
    return $this->server->get('grp_memb_attr_match_user_attr') && $this->server->get('grp_memb_attr');
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
    for ($key = 0; $key < count($or_filters); $key = $key + self::LDAP_QUERY_CHUNK) {
      $current_or_filters = array_slice($or_filters, $key, self::LDAP_QUERY_CHUNK);
      // Example 1: (|(cn=group1)(cn=group2))
      // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
      $orFilter = '(|(' . implode(")(", $current_or_filters) . '))';
      $query_for_parent_groups = '(&(objectClass=' . $this->server->get('grp_object_cat') . ')' . $orFilter . ')';

      // Need to search on all base DN one at a time.
      foreach ($this->server->getBaseDn() as $base_dn) {
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
        if ($ldap_result->count() > 0 && $level < self::LDAP_QUERY_RECURSION_LIMIT) {
          $tested_group_ids = [];
          $this->groupMembershipsFromEntryRecursive($ldap_result, $all_group_dns, $tested_group_ids, $level + 1, self::LDAP_QUERY_RECURSION_LIMIT);
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
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if ($this->checkDnExists($group_dn)) {
      return FALSE;
    }

    $attributes = array_change_key_case($attributes, CASE_LOWER);
    if (empty($attributes['objectclass'])) {
      $objectClass = $this->server->get('grp_object_cat');
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
    try {
      $this->ldap->getEntryManager()->add($entry);
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP server %id exception: %ldap_error", [
        '%id' => $this->server->id(),
        '%ldap_error' => $e->getMessage(),
      ]
      );
      return FALSE;
    }

    $this->moduleHandler->invokeAll('ldap_entry_post_provision', [
      $ldap_entries,
      $this,
      $context,
    ]
    );
    return TRUE;
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
   *
   * @TODO: When actually in use split into two to remove boolean modifier.
   */
  public function groupRemoveGroup($group_dn, $only_if_group_empty = TRUE) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

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
   * @FIXME symfony/ldap refactoring needed.
   */
  public function groupAddMember($group_dn, $user) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    $result = FALSE;
    if ($this->groupGroupEntryMembershipsConfigured()) {
      try {
        $entry = new Entry($group_dn);
        // TODO: Bugreport upstream interface.
        /** @var \Symfony\Component\Ldap\Adapter\ExtLdap\EntryManager $manager */
        $manager = $this->ldap->getEntryManager();
        $manager->addAttributeValues($entry, $this->server->get('grp_memb_attr'), [$user]);
        $result = TRUE;
      }
      catch (LdapException $e) {
        $this->logger->error("LDAP server error updating %dn on @sid exception: %ldap_error", [
          '%dn' => $entry->getDn(),
          '@sid' => $this->server->id(),
          '%ldap_error' => $e->getMessage(),
        ]
        );
      }
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
   */
  public function groupRemoveMember($group_dn, $member) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    $result = FALSE;
    if ($this->groupGroupEntryMembershipsConfigured()) {
      try {
        $entry = new Entry($group_dn);
        // TODO: Bugreport upstream interface.
        /** @var \Symfony\Component\Ldap\Adapter\ExtLdap\EntryManager $manager */
        $manager = $this->ldap->getEntryManager();
        $manager->removeAttributeValues($entry, $this->server->get('grp_memb_attr'), [$member]);
        $result = TRUE;
      }
      catch (LdapException $e) {
        $this->logger->error("LDAP server error updating %dn on @sid exception: %ldap_error", [
          '%dn' => $entry->getDn(),
          '@sid' => $this->server->id(),
          '%ldap_error' => $e->getMessage(),
        ]
        );
      }
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
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }

    $attributes = [$this->server->get('grp_memb_attr'), 'cn', 'objectclass'];
    $group_entry = $this->checkDnExistsIncludeData($group_dn, $attributes);
    if (!$group_entry) {
      return FALSE;
    }
    else {
      // If attributes weren't returned, don't give false  empty group.
      if (empty($group_entry->getAttribute('cn'))) {
        return FALSE;
      }
      if (empty($group_entry->getAttribute($this->server->get('grp_memb_attr')))) {
        // If no attribute returned, no members.
        return [];
      }
      $members = $group_entry->getAttribute($this->server->get('grp_memb_attr'));

      $result = $this->groupMembersRecursive($group_entry, $members, [], 0, self::LDAP_QUERY_RECURSION_LIMIT);
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
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }

    $attributes = [$this->server->get('grp_memb_attr'), 'cn', 'objectclass'];
    $group_entry = $this->checkDnExistsIncludeData($group_dn, $attributes);
    if (!$group_entry) {
      return FALSE;
    }
    else {
      // If attributes weren't returned, don't give false, give empty group.
      if (!$group_entry->hasAttribute('cn')) {
        return FALSE;
      }
      if (!$group_entry->hasAttribute($this->server->get('grp_memb_attr'))) {
        // If no attribute returned, no members.
        return [];
      }
      else {
        return $group_entry->getAttribute($this->server->get('grp_memb_attr'));
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
    if (!$this->checkAvailability()) {
      return FALSE;
    }

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
   * @param \Symfony\Component\Ldap\Entry $group_dn_entries
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
   *
   *   Todo: Should the type hint for Entry not be Entry[]?
   */
  public function groupMembersRecursive(Entry $group_dn_entries, array &$all_member_dns, array $tested_group_dns, $level, $max_levels, $object_classes = FALSE) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (!$this->groupGroupEntryMembershipsConfigured() || !is_array($group_dn_entries)) {
      return FALSE;
    }

    foreach ($group_dn_entries as $member_entry) {
      // 1.  Add entry itself if of the correct type to $all_member_dns.
      $object_class_match = (!$object_classes || (count(array_intersect(array_values($member_entry['objectclass']), $object_classes)) > 0));
      $object_is_group = in_array($this->server->get('grp_object_cat'), array_map('strtolower', array_values($member_entry['objectclass'])));
      // Add member.
      if ($object_class_match && !in_array($member_entry['dn'], $all_member_dns)) {
        $all_member_dns[] = $member_entry['dn'];
      }

      // 2. If its a group, keep recurse the group for descendants.
      if ($object_is_group && $level < $max_levels) {
        if ($this->server->get('grp_memb_attr_match_user_attr') == 'dn') {
          $group_id = $member_entry['dn'];
        }
        else {
          $group_id = $member_entry[$this->server->get('grp_memb_attr_match_user_attr')][0];
        }
        // 3. skip any groups that have already been tested.
        if (!in_array($group_id, $tested_group_dns)) {
          $tested_group_dns[] = $group_id;
          $member_ids = $member_entry[$this->server->get('grp_memb_attr')];

          if (count($member_ids)) {
            // Example 1: (|(cn=group1)(cn=group2))
            // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
            $query_for_child_members = '(|(' . implode(")(", $member_ids) . '))';
            // Add or on object classes, otherwise get all object classes.
            if ($object_classes && count($object_classes)) {
              $object_classes_ors = ['(objectClass=' . $this->server->get('grp_object_cat') . ')'];
              foreach ($object_classes as $object_class) {
                $object_classes_ors[] = '(objectClass=' . $object_class . ')';
              }
              $query_for_child_members = '&(|' . implode($object_classes_ors) . ')(' . $query_for_child_members . ')';
            }

            $return_attributes = [
              'objectclass',
              $this->server->get('grp_memb_attr'),
              $this->server->get('grp_memb_attr_match_user_attr'),
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
   * @param string $username
   *   A Drupal user entity.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   */
  public function groupMembershipsFromUser($username) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    $group_dns = FALSE;
    $user_ldap_entry = $this->matchUsernameToExistingLdapEntry($username);
    if (!$user_ldap_entry || $this->server->get('grp_unused')) {
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
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (!$this->groupUserMembershipsFromAttributeConfigured()) {
      return FALSE;
    }

    $groupAttribute = $this->server->get('grp_user_memb_attr');

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
      if ($this->server->get('grp_nested')) {
        if ($this->server->get('grp_memb_attr_match_user_attr') == 'dn') {
          $member_value = $memberGroupDn;
        }
        else {
          $member_value = $this->getFirstRdnValueFromDn($memberGroupDn, $this->server->get('grp_memb_attr_match_user_attr'));
        }
        $orFilters[] = $this->server->get('grp_memb_attr') . '=' . $this->ldapEscapeDn($member_value);
      }
    }

    if ($this->server->get('grp_nested') && count($orFilters)) {
      $allGroupDns = $this->getNestedGroupDnFilters($allGroupDns, $orFilters, $level);
    }

    return $allGroupDns;
  }

  /**
   * Get list of all groups that a user is a member of by querying groups.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   LDAP entry.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   *
   * @see groupMembershipsFromUser()
   */
  public function groupUserMembershipsFromEntry(Entry $ldap_entry) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }

    // MIXED CASE VALUES.
    $all_group_dns = [];
    // Array of dns already tested to avoid excess queries MIXED CASE VALUES.
    $tested_group_ids = [];
    $level = 0;

    if ($this->server->get('grp_memb_attr_match_user_attr') == 'dn') {
      $member_value = $ldap_entry->getDn();
    }
    else {
      $member_value = $ldap_entry->getAttribute($this->server->get('grp_memb_attr_match_user_attr'))[0];
    }

    // Need to search on all basedns one at a time.
    foreach ($this->server->getBaseDn() as $baseDn) {
      // Only need dn, so empty array forces return of no attributes.
      // TODO: See if this syntax is correct and returns us valid DN with no attributes.
      try {
        $group_query = '(&(objectClass=' . $this->server->get('grp_object_cat') . ')(' . $this->server->get('grp_memb_attr') . "=$member_value))";
        $ldap_result = $this->ldap->query($baseDn, $group_query, ['filter' => []])->execute();
      }
      catch (LdapException $e) {
        $this->logger->critical('LDAP search error with %message', [
          '%message' => $e->getMessage(),
        ]);
        continue;
      }

      if ($ldap_result->count() > 0) {
        $maxLevels = $this->server->get('grp_nested') ? self::LDAP_QUERY_RECURSION_LIMIT : 0;
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
      if ($this->server->get('grp_memb_attr_match_user_attr') == 'dn') {
        $member_id = $group_entry->getDn();
      }
      // Maybe cn, uid, etc is held.
      else {
        $member_id = $this->getFirstRdnValueFromDn($group_entry->getDn(), $this->server->get('grp_memb_attr_match_user_attr'));
      }

      if ($member_id && !in_array($member_id, $tested_group_ids)) {
        $tested_group_ids[] = $member_id;
        $all_group_dns[] = $group_entry->getDn();
        // Add $group_id (dn, cn, uid) to query.
        $or_filters[] = $this->server->get('grp_memb_attr') . '=' . $this->ldapEscapeDn($member_id);
      }
    }

    if (count($or_filters)) {
      // Only 50 or so per query.
      // TODO: We can likely remove this since we are fetching one result at a
      // time with symfony/ldap.
      for ($key = 0; $key < count($or_filters); $key = $key + self::LDAP_QUERY_CHUNK) {
        $current_or_filters = array_slice($or_filters, $key, self::LDAP_QUERY_CHUNK);
        // Example 1: (|(cn=group1)(cn=group2))
        // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
        $or = '(|(' . implode(")(", $current_or_filters) . '))';
        $query_for_parent_groups = '(&(objectClass=' . $this->server->get('grp_object_cat') . ')' . $or . ')';

        // Need to search on all base DNs one at a time.
        foreach ($this->server->getBaseDn() as $base_dn) {
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
   * @param string $username
   *   A username.
   *
   * @return array|bool
   *   Array of group strings.
   */
  public function groupUserMembershipsFromDn($username) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (!$this->server->get('grp_derive_from_dn') || !$this->server->get('grp_derive_from_dn_attr')) {
      return FALSE;
    }

    if ($ldap_entry = $this->matchUsernameToExistingLdapEntry($username)) {
      return $this->getAllRdnValuesFromDn($ldap_entry->getDn(), $this->server->get('grp_derive_from_dn_attr'));
    }
    return FALSE;
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
    $pairs = $this->splitDnWithAttributes($dn);
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
  public function getAllRdnValuesFromDn($dn, $rdn) {
    // Escapes attribute values, need to be unescaped later.
    $pairs = $this->splitDnWithAttributes($dn);
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

}
