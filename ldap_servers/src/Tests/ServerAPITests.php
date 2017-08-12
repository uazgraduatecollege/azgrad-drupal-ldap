<?php

namespace Drupal\ldap_servers\tests;

use Drupal\Component\Utility\Unicode;

/**
 * Legacy tests.
 *
 * @FIXME: Placeholder for remaining unported functions from legacy tests.
 */
class ServerAPITests {

  /**
   * Legacy test placeholder.
   */
  public function testInstall() {

    return;
    // Maybe: WebTestcase to verify that all modules can be cleanly installed.
  }

  // @codingStandardsIgnoreStart
  /**
   * Bind.
   *
   * @TODO: Review for unit tests on bind()
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
    $watchdog_tokens = ['%user' => $userdn, '%errno' => $ldap_errno, '%error' => $ldap_error];
    watchdog('ldap', "LDAP bind failure for user %user. Error %errno: %error", $watchdog_tokens);
    return $ldap_errno;

  }

  /**
   * TODO: Review for unit tests of search()
   *
   * @param null $base_dn
   *   Unknown.
   * @param string $filter
   *   The search filter. such as sAMAccountName=jbarclay.
   * @param array $attributes
   *   List of desired attributes. If omitted, we only return "dn".
   * @param int $attrsonly
   *   Unknown.
   * @param int $sizelimit
   *   Unknown.
   * @param int $timelimit
   *   Unknown.
   * @param int|null $deref
   *   Unknown.
   * @param null $scope
   *   Unknown.
   *
   * @return array|bool
   *   An array of matching entries->attributes, or FALSE if the search is
   *   empty.
   *
   * @internal param string $basedn The search base. If NULL, we use $this->basedn.*   The search base. If NULL, we use $this->basedn.
   */
  public function search($base_dn = NULL, $filter, $attributes = [], $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER, $scope = NULL) {
    if ($scope == NULL) {
      $scope = Server::SCOPE_SUBTREE;
    }

    $lcase_attribute = [];
    foreach ($attributes as $i => $attribute_name) {
      $lcase_attribute[] = Unicode::strtolower($attribute_name);
    }
    $attributes = $lcase_attribute;

    // For test matching simplicity remove line breaks and tab spacing.
    $filter = trim(str_replace(["\n", "  "], ['', ''], $filter));

    if ($base_dn == NULL) {
      if (count($this->getBaseDn()) == 1) {
        $base_dn = $this->getBaseDn()[0];
      }
      else {
        return FALSE;
      }
    }

    // Search CASE 1: for some mock LDAP servers, a set of fixed LDAP filters
    // are prepolulated in test data.
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
     * Search CASE 2: attempt to programmatically evaluate LDAP filter
     * by looping through fake LDAP entries
     */
    $base_dn = Unicode::strtolower($base_dn);
    $filter = trim($filter, "()");
    $subqueries = [];
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

    // Need to perform faux LDAP search here with data in.
    $results = [];

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
            $selected_data = [];
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
            $selected_data = [];
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
  // @codingStandardsIgnoreEnd
}
