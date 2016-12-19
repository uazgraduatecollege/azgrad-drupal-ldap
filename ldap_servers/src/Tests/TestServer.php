<?php

namespace Drupal\ldap_servers\tests;

use Drupal\Component\Utility\Unicode;
use Drupal\ldap_servers\Entity\Server;

/**
 * The test server to allow for mocking complex communications with ldap_server.
 * @FIXME: Clean Reimplementation probably more useful.
 */
class TestServer extends Server {

  public $entries;
  public $methodResponses;
  public $searchResults;
  // Default to an anonymous bind.
  public $binddn = FALSE;
  // Default to an anonymous bind.
  public $bindpw = FALSE;

  /**
   * Constructor Method.
   *
   * Can take array of form property_name => property_value
   * or $sid, where sid is used to derive the include file.
   */
  public function __construct($sid) {
    parent::__construct($sid, 'ldap_server');
    if (!is_scalar($sid)) {
      $test_data = $sid;
      $sid = $test_data['sid'];
    }
    else {
      $test_data = variable_get('ldap_test_server__' . $sid, array());
    }

    $bindpw = (isset($test_data['bindpw'])) ? $test_data['bindpw'] : 'goodpwd';
    $this->sid = $sid;
    $this->refreshFakeData();
    $this->initDerivedProperties($bindpw);
  }

  /**
   *
   */
  public function refreshFakeData() {

    $test_data = variable_get('ldap_test_server__' . $this->sid, array());
    $this->methodResponses = (is_array($test_data) && isset($test_data['methodResponses'])) ? $test_data['methodResponses'] : array();
    $this->entries = (is_array($test_data) && isset($test_data['ldap'])) ? $test_data['ldap'] : array();

    $this->searchResults = (isset($test_data['search_results'])) ? $test_data['search_results'] : array();
    $this->detailedWatchdogLog = config('ldap_help.settings')->get('watchdog_detail');
    foreach ($test_data['properties'] as $property_name => $property_value) {
      $this->{$property_name} = $property_value;
    }
    // $this->basedn = unserialize($this->basedn);.
  }

  /**
   * Connect Method.
   */
  public function connect() {
    return $this->methodResponses['connect'];
  }

  /**
   *
   */
  public function bind($userdn = NULL, $pass = NULL, $anon_bind = FALSE) {
    $userdn = ($userdn != NULL) ? $userdn : $this->binddn;
    $pass = ($pass != NULL) ? $pass : $this->bindpw;

    if (!isset($this->entries[$userdn])) {
      // 0x20 or 32.
      $ldap_errno = self::LDAP_NO_SUCH_OBJECT;
      if (function_exists('ldap_err2str')) {
        $ldap_error = ldap_err2str($ldap_errno);
      }
      else {
        $ldap_error = "Failed to find $userdn in LdapServerTest.class.php";
      }
    }
    elseif (isset($this->entries[$userdn]['password'][0]) && $this->entries[$userdn]['password'][0] == $pass && $pass) {
      return self::LDAP_SUCCESS;
    }
    else {
      if (!$pass) {
        debug("Simpletest failure for $userdn.  No password submitted");
      }
      if (!isset($this->entries[$userdn]['password'][0])) {
        debug("Simpletest failure for $userdn.  No password in entry to test for bind"); debug($this->entries[$userdn]);
      }
      $ldap_errno = self::LDAP_INVALID_CREDENTIALS;
      if (function_exists('ldap_err2str')) {
        $ldap_error = ldap_err2str($ldap_errno);
      }
      else {
        $ldap_error = "Credentials for $userdn failed in LdapServerTest.class.php";
      }
    }
    // @FIXME: watchdog
    $watchdog_tokens = array('%user' => $userdn, '%errno' => $ldap_errno, '%error' => $ldap_error);
    watchdog('ldap', "LDAP bind failure for user %user. Error %errno: %error", $watchdog_tokens);
    return $ldap_errno;

  }

  /**
   * Disconnect (unbind) from an active LDAP server.
   */
  public function disconnect() {

  }

  /**
   * Perform an LDAP search.
   *
   * @param null $base_dn
   * @param string $filter
   *   The search filter. such as sAMAccountName=jbarclay.
   * @param array $attributes
   *   List of desired attributes. If omitted, we only return "dn".
   *
   * @param int $attrsonly
   * @param int $sizelimit
   * @param int $timelimit
   * @param int|null $deref
   * @param null $scope
   *
   * @return array|bool An array of matching entries->attributes, or FALSE if the search is
   *   An array of matching entries->attributes, or FALSE if the search is
   *   empty.
   *
   * @internal param string $basedn The search base. If NULL, we use $this->basedn.*   The search base. If NULL, we use $this->basedn.
   */
  public function search($base_dn = NULL, $filter, $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER, $scope = NULL) {
    if ($scope == NULL) {
      $scope = Server::$scopeSubTree;
    }

    $lcase_attribute = array();
    foreach ($attributes as $i => $attribute_name) {
      $lcase_attribute[] = Unicode::strtolower($attribute_name);
    }
    $attributes = $lcase_attribute;

    // For test matching simplicity remove line breaks and tab spacing.
    $filter = trim(str_replace(array("\n", "  "), array('', ''), $filter));

    if ($base_dn == NULL) {
      if (count($this->getBasedn()) == 1) {
        $base_dn = $this->getBasedn()[0];
      }
      else {
        return FALSE;
      }
    }

    /**
     * Search CASE 1: for some mock ldap servers, a set of fixed ldap filters
     * are prepolulated in test data
     */
    if (isset($this->searchResults[$filter][$base_dn])) {
      $results = $this->searchResults[$filter][$base_dn];
      foreach ($results as $i => $entry) {
        if (is_array($entry) && isset($entry['FULLENTRY'])) {
          unset($results[$i]['FULLENTRY']);
          $dn = $results[$i]['dn'];
          $results[$i] = $this->entries[$dn];
          $results[$i]['dn'] = $dn;
        }
      }
      return $results;
    }

    /**
     * Search CASE 2: attempt to programmatically evaluate ldap filter
     * by looping through fake ldap entries
     */
    $base_dn = Unicode::strtolower($base_dn);
    $filter = trim($filter, "()");
    $subqueries = array();
    $operand = FALSE;

    if (strpos($filter, '&') === 0) {
      /**
       * case 2.A.: filter of form (&(<attribute>=<value>)(<attribute>=<value>)(<attribute>=<value>))
       *  such as (&(samaccountname=hpotter)(samaccountname=hpotter)(samaccountname=hpotter))
       */
      $operand = '&';
      $filter = substr($filter, 1);
      $filter = trim($filter, "()");
      $parts = explode(')(', $filter);
      foreach ($parts as $i => $pair) {
        $subqueries[] = explode('=', $pair);
      }
    }
    elseif (strpos($filter, '|') === 0) {
      /**
       * case 2.B: filter of form (|(<attribute>=<value>)(<attribute>=<value>)(<attribute>=<value>))
       *  such as (|(samaccountname=hpotter)(samaccountname=hpotter)(samaccountname=hpotter))
       */
      $operand = '|';
      $filter = substr($filter, 1);
      $filter = trim($filter, "()");
      $parts = explode(')(', $filter);
      $parts = explode(')(', $filter);
      foreach ($parts as $i => $pair) {
        $subqueries[] = explode('=', $pair);
      }
    }
    elseif (count(explode('=', $filter)) == 2) {
      /**
       * case 2.C.: filter of form (<attribute>=<value>)
       *  such as (samaccountname=hpotter)
       */
      $operand = '|';
      $subqueries[] = explode('=', $filter);
    }
    else {
      return FALSE;
    }

    // Need to perform faux ldap search here with data in.
    $results = array();

    if ($operand == '|') {
      foreach ($subqueries as $i => $subquery) {
        $filter_attribute = Unicode::strtolower($subquery[0]);
        $filter_value = $subquery[1];

        foreach ($this->entries as $dn => $entry) {
          $dn_lcase = Unicode::strtolower($dn);

          // If not in basedn, skip
          // eg. basedn ou=campus accounts,dc=ad,dc=myuniversity,dc=edu
          // should be leftmost string in:
          // cn=jdoe,ou=campus accounts,dc=ad,dc=myuniversity,dc=edu
          // $pos = strpos($dn_lcase, $base_dn);.
          $substring = strrev(substr(strrev($dn_lcase), 0, strlen($base_dn)));
          $cascmp = strcasecmp($base_dn, $substring);
          if ($cascmp !== 0) {

            // Not in basedn.
            continue;
          }
          // If doesn't filter attribute has no data, continue.
          $attr_value_to_compare = FALSE;
          foreach ($entry as $attr_name => $attr_value) {
            if (Unicode::strtolower($attr_name) == $filter_attribute) {
              $attr_value_to_compare = $attr_value;
              break;
            }
          }
          if (!$attr_value_to_compare || Unicode::strtolower($attr_value_to_compare[0]) != $filter_value) {
            continue;
          }

          // match!
          $entry['dn'] = $dn;
          if ($attributes) {
            $selected_data = array();
            foreach ($attributes as $i => $attr_name) {
              $selected_data[$attr_name] = (isset($entry[$attr_name])) ? $entry[$attr_name] : NULL;
            }
            $results[] = $selected_data;
          }
          else {
            $results[] = $entry;
          }
        }
      }
    }
    // Reverse the loops.
    elseif ($operand == '&') {
      foreach ($this->entries as $dn => $entry) {
        $dn_lcase = Unicode::strtolower($dn);
        // Until 1 subquery fails.
        $match = TRUE;
        foreach ($subqueries as $i => $subquery) {
          $filter_attribute = Unicode::strtolower($subquery[0]);
          $filter_value = $subquery[1];

          $substring = strrev(substr(strrev($dn_lcase), 0, strlen($base_dn)));
          $cascmp = strcasecmp($base_dn, $substring);
          if ($cascmp !== 0) {
            $match = FALSE;
            // Not in basedn.
            break;
          }
          // If doesn't filter attribute has no data, continue.
          $attr_value_to_compare = FALSE;
          foreach ($entry as $attr_name => $attr_value) {
            if (Unicode::strtolower($attr_name) == $filter_attribute) {
              $attr_value_to_compare = $attr_value;
              break;
            }
          }
          if (!$attr_value_to_compare || Unicode::strtolower($attr_value_to_compare[0]) != $filter_value) {
            $match = FALSE;
            // Not in basedn.
            break;
          }

        }
        if ($match === TRUE) {
          $entry['dn'] = $dn;
          if ($attributes) {
            $selected_data = array();
            foreach ($attributes as $i => $attr_name) {
              $selected_data[$attr_name] = (isset($entry[$attr_name])) ? $entry[$attr_name] : NULL;
            }
            $results[] = $selected_data;
          }
          else {
            $results[] = $entry;
          }
        }
      }
    }

    $results['count'] = count($results);
    return $results;
  }

  /**
   * Does dn exist for this server?
   *
   * @param string $dn
   * @param enum $return
   *   = 'boolean' or 'ldap_entry'.
   *
   * @param return FALSE or ldap entry array
   */
  public function dnExists($find_dn, $return = 'boolean', $attributes = array('objectclass')) {
    $this->refreshFakeData();
    $test_data = variable_get('ldap_test_server__' . $this->sid, array());
    foreach ($this->entries as $entry_dn => $entry) {
      $match = (strcasecmp($entry_dn, $find_dn) == 0);

      if ($match) {
        return ($return == 'boolean') ? TRUE : $entry;
      }
    }
    // not match found in loop.
    return FALSE;

  }

  /**
   *
   */
  public function countEntries($ldap_result) {
    return ldap_count_entries($this->connection, $ldap_result);
  }

  /**
   *
   */
  public static function getLdapServerObjects($sid = NULL, $type = NULL, $flatten = FALSE) {
    $servers = array();
    if ($sid) {
      $servers[$sid] = new TestServer($sid);
    }
    else {
      $server_ids = variable_get('ldap_test_servers', array());
      foreach ($server_ids as $sid => $_sid) {
        $servers[$sid] = new TestServer($sid);
      }
    }

    if ($flatten && $sid) {
      return $servers[$sid];
    }
    else {
      return $servers;
    }
  }

  /**
   * Create ldap entry.
   *
   * @param array $ldap_entry
   *   should follow the structure of ldap_add functions
   *   entry array: http://us.php.net/manual/en/function.ldap-add.php
   *   $attributes["attribute1"] = "value";
   *   $attributes["attribute2"][0] = "value1";
   *   $attributes["attribute2"][1] = "value2";.
   *
   * @return boolean result
   */
  public function createLdapEntry($ldap_entry, $dn = NULL) {
    $result = FALSE;
    $test_data = variable_get('ldap_test_server__' . $this->sid, array());

    if (isset($ldap_entry['dn'])) {
      $dn = $ldap_entry['dn'];
      unset($ldap_entry['dn']);
    }

    if ($dn && !isset($test_data['entries'][$dn])) {
      $test_data['entries'][$dn] = $ldap_entry;
      $test_data['ldap'][$dn] = $ldap_entry;
      variable_set('ldap_test_server__' . $this->sid, $test_data);
      $this->refreshFakeData();
      $result = TRUE;
    }
    return $result;
  }

  /**
   *
   */
  public function modifyLdapEntry($dn, $attributes = NULL, $old_attributes = FALSE) {
    if (!$attributes) {
      $attributes = array();
    }
    $test_data = variable_get('ldap_test_server__' . $this->sid, array());
    if (!isset($test_data['entries'][$dn])) {
      return FALSE;
    }
    $ldap_entry = $test_data['entries'][$dn];

    foreach ($attributes as $key => $cur_val) {
      if ($cur_val == '') {
        unset($ldap_entry[$key]);
      }
      elseif (is_array($cur_val)) {
        foreach ($cur_val as $mv_key => $mv_cur_val) {
          if ($mv_cur_val == '') {
            unset($ldap_entry[$key][$mv_key]);
          }
          else {
            if (is_array($mv_cur_val)) {
              $ldap_entry[$key][$mv_key] = $mv_cur_val;
            }
            else {
              $ldap_entry[$key][$mv_key][] = $mv_cur_val;
            }
          }
        }
        unset($ldap_entry[$key]['count']);
        $ldap_entry[$key]['count'] = count($ldap_entry[$key]);
      }
      else {
        $ldap_entry[$key][0] = $cur_val;
        $ldap_entry[$key]['count'] = count($ldap_entry[$key]);
      }
    }

    $test_data['entries'][$dn] = $ldap_entry;
    $test_data['ldap'][$dn] = $ldap_entry;
    variable_set('ldap_test_server__' . $this->sid, $test_data);
    $this->refreshFakeData();
    return TRUE;

  }

  /**
   * Perform an LDAP delete.
   *
   * @param string $dn
   *
   * @return boolean result per ldap_delete
   *
   * @TODO: Might not be necessary anymore.
   */
  public function ldapDelete($dn) {

    $test_data = variable_get('ldap_test_server__' . $this->sid, array());
    $deleted = FALSE;
    foreach (array('entries', 'users', 'groups', 'ldap') as $test_data_sub_array) {
      if (isset($test_data[$test_data_sub_array][$dn])) {
        unset($test_data[$test_data_sub_array][$dn]);
        $deleted = TRUE;
      }
    }
    if ($deleted) {
      variable_set('ldap_test_server__' . $this->sid, $test_data);
      $this->refreshFakeData();
      return TRUE;
    }
    else {
      return FALSE;
    }

  }

}
