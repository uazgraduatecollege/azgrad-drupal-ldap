<?php

namespace Drupal\ldap_servers\Entity;

use Drupal\Component\Utility\Unicode;
use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapProtocolInterface;
use Drupal\ldap_servers\Helper\MassageAttributes;
use Drupal\ldap_servers\ServerInterface;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\user\Entity\User;

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
 *   admin_permission = "administer site configuration",
 *   entity_keys = {
 *     "id" = "id",
 *     "label" = "label",
 *     "uuid" = "uuid"
 *   },
 *   links = {
 *     "canonical" = "/admin/config/people/ldap/server/{server}",
 *     "edit-form" = "/admin/config/people/ldap/server/{server}/edit",
 *     "delete-form" = "/admin/config/people/ldap/server/{server}/delete",
 *     "collection" = "/admin/config/people/ldap/server"
 *   }
 * )
 */
class Server extends ConfigEntityBase implements ServerInterface, LdapProtocolInterface {

  protected $id;
  protected $label;
  protected $connection;

  const LDAP_OPT_DIAGNOSTIC_MESSAGE_BYTE = 0x0032;
  const LDAP_SERVER_LDAP_QUERY_CHUNK = 50;
  const LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT = 10;

  const SCOPE_BASE = 1;
  const SCOPE_ONE_LEVEL = 2;
  const SCOPE_SUBTREE = 3;

  private $searchPageStart = 0;
  private $searchPageEnd = NULL;

  /**
   * Error methods and properties.
   *
   * @var bool
   */
  public $detailedWatchdogLog = FALSE;

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
   * Connects to the LDAP server.
   *
   * @return int
   *   LDAP_SUCCESS or the relevant error.
   */
  public function connect() {
    $port = (self::get('port'));
    $address = (self::get('address'));

    $con = ldap_connect($address, $port);

    if (!$con) {
      \Drupal::logger('user')->notice(
        'LDAP Connect failure to @address on port @port.',
        ['@address' => $address, '@port' => $port]
      );
      return self::LDAP_CONNECT_ERROR;
    }

    ldap_set_option($con, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($con, LDAP_OPT_REFERRALS, 0);

    // Use TLS if we are configured and able to.
    if (self::get('tls')) {
      ldap_get_option($con, LDAP_OPT_PROTOCOL_VERSION, $vers);
      if ($vers == -1) {
        \Drupal::logger('user')->notice('Could not get LDAP protocol version.');
        return self::LDAP_PROTOCOL_ERROR;
      }
      if ($vers != 3) {
        \Drupal::logger('user')->notice('Could not start TLS, only supported by LDAP v3.');
        return self::LDAP_CONNECT_ERROR;
      }
      elseif (!function_exists('ldap_start_tls')) {
        \Drupal::logger('user')->notice('Could not start TLS. It does not seem to be supported by this PHP setup.');
        return self::LDAP_CONNECT_ERROR;
      }
      elseif (!ldap_start_tls($con)) {
        \Drupal::logger('user')->notice('Could not start TLS. (Error @errno: @error).', ['@errno' => ldap_errno($con), '@error' => ldap_error($con)]);
        return self::LDAP_CONNECT_ERROR;
      }
    }

    // Store the resulting resource.
    $this->connection = $con;
    return self::LDAP_SUCCESS;
  }

  /**
   * Bind (authenticate) against an active LDAP database.
   *
   * @param string $userdn
   *   The DN to bind against. If NULL, we use $this->binddn.
   * @param string $pass
   *   The password search base. If NULL, we use $this->bindpw.
   * @param bool $anon_bind
   *   Whether to bind anonymously.
   *
   * @return int
   *   Result of bind in form of LDAP_SUCCESS or relevant error.
   */
  public function bind($userdn = NULL, $pass = NULL, $anon_bind = NULL) {
    // Ensure that we have an active server connection.
    if (!$this->connection) {
      \Drupal::logger('ldap_servers')->notice("LDAP bind failure for user %user. Not connected to LDAP server.", ['%user' => $userdn]);
      return self::LDAP_CONNECT_ERROR;
    }

    if ($anon_bind === FALSE && $userdn === NULL && $pass === NULL && $this->get('bind_method') == 'anon') {
      $anon_bind = TRUE;
    }
    if ($anon_bind === TRUE) {
      if (@!ldap_bind($this->connection)) {
        if ($this->detailedWatchdogLog) {
          \Drupal::logger('ldap_servers')->notice("LDAP anonymous bind error. Error %error", ['%error' => $this->formattedError($this->ldapErrorNumber())]);
        }
        return ldap_errno($this->connection);
      }
    }
    else {
      $userdn = ($userdn != NULL) ? $userdn : $this->get('binddn');
      $pass = ($pass != NULL) ? $pass : $this->get('bindpw');

      if (Unicode::strlen($pass) == 0 || Unicode::strlen($userdn) == 0) {
        \Drupal::logger('ldap_servers')
          ->notice("LDAP bind failure for user userdn=%userdn, pass=%pass.", [
            '%userdn' => $userdn,
            '%pass' => $pass,
          ]);
        return self::LDAP_LOCAL_ERROR;
      }
      if (@!ldap_bind($this->connection, $userdn, $pass)) {
        if ($this->detailedWatchdogLog) {
          \Drupal::logger('ldap_servers')
            ->notice("LDAP bind failure for user %user. Error %errno: %error", [
              '%user' => $userdn,
              '%errno' => ldap_errno($this->connection),
              '%error' => ldap_error($this->connection),
            ]);
        }
        return ldap_errno($this->connection);
      }
    }
    return self::LDAP_SUCCESS;
  }

  /**
   * Disconnect (unbind) from an active LDAP server.
   */
  public function disconnect() {
    if (!$this->connection) {
      // Never bound or not currently bound, so no need to disconnect.
    }
    else {
      ldap_unbind($this->connection);
      $this->connection = NULL;
    }
  }

  /**
   * Checks if connected and connects and binds otherwise.
   */
  public function connectAndBindIfNotAlready() {
    if (!$this->connection) {
      $this->connect();
      $this->bind();
    }
  }

  /**
   * Does dn exist for this server?
   *
   * @param string $dn
   *   DN to search for.
   * @param string $return
   *   Parameter with value 'boolean' or 'ldap_entry'.
   * @param array $attributes
   *   In same form as ldap_read $attributes parameter.
   *
   * @return bool|array
   *   Return FALSE or LDAP entry array.
   *
   * @TODO: Handle case (in)sensitivity cleanly.
   */
  public function dnExists($dn, $return = 'boolean', array $attributes = NULL) {

    $params = [
      'base_dn' => $dn,
      'attributes' => $attributes,
      'attrsonly' => FALSE,
      'filter' => '(objectclass=*)',
      'sizelimit' => 0,
      'timelimit' => 0,
      'deref' => NULL,
    ];

    if ($return == 'boolean' || !is_array($attributes)) {
      $params['attributes'] = ['objectclass'];
    }
    else {
      $params['attributes'] = $attributes;
    }

    $result = $this->ldapQuery(Server::SCOPE_BASE, $params);
    if ($result !== FALSE) {
      $entries = @ldap_get_entries($this->connection, $result);
      if ($entries !== FALSE && $entries['count'] > 0) {
        return ($return == 'boolean') ? TRUE : $entries[0];
      }
    }

    return FALSE;

  }

  /**
   * Count LDAP entries.
   *
   * @param resource $ldap_result
   *   The LDAP link identifier.
   *
   * @return int|bool
   *   Return false on error or number of entries, if 0 entries will return 0.
   */
  public function countEntries($ldap_result) {
    return ldap_count_entries($this->connection, $ldap_result);
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
   */
  public function createLdapEntry(array $attributes, $dn = NULL) {

    if (!$this->connection) {
      $this->connect();
      $this->bind();
    }
    if (isset($attributes['dn'])) {
      $dn = $attributes['dn'];
      unset($attributes['dn']);
    }
    elseif (!$dn) {
      return FALSE;
    }
    if (!empty($attributes['unicodePwd']) && $this->get('type') == 'ad') {
      $attributes['unicodePwd'] = $this->convertPasswordForActiveDirectoryunicodePwd($attributes['unicodePwd']);
    }

    $result = @ldap_add($this->connection, $dn, $attributes);
    if (!$result) {
      ldap_get_option($this->connection, self::LDAP_OPT_DIAGNOSTIC_MESSAGE_BYTE, $ldap_additional_info);

      \Drupal::logger('ldap_servers')->error(
        "LDAP Server ldap_add(%dn) Error Server ID = %id, LDAP Error %ldap_error. LDAP Additional info: %ldap_additional_info", [
          '%dn' => $dn,
          '%id' => $this->id(),
          '%ldap_error' => $this->formattedError($this->ldapErrorNumber()),
          '%ldap_additional_info' => $ldap_additional_info,
        ]);
    }

    return $result;
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
    if (!$this->connection) {
      $this->connect();
      $this->bind();
    }
    $result = @ldap_delete($this->connection, $dn);

    if (!$result) {
      \Drupal::logger('ldap_servers')->error(
        "LDAP Server delete(%dn) in LdapServer::delete() Error Server ID = %id, LDAP Error %ldap_error.", [
          '%dn' => $dn,
          '%id' => $this->id(),
          '%ldap_error' => $this->formattedError($this->ldapErrorNumber()),
        ]);
    }
    return $result;
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
   * @param array $new_entry
   *   LDAP entry in form <attribute> => <value>.
   * @param array $old_entry
   *   LDAP entry in form <attribute> => ['count' => N, [<value>,...<value>]].
   *
   * @return array
   *   LDAP entry with no values that have NOT changed.
   */
  public static function removeUnchangedAttributes(array $new_entry, array $old_entry) {

    foreach ($new_entry as $key => $new_val) {
      $old_value = FALSE;
      $old_value_is_scalar = NULL;
      $key_lcase = Unicode::strtolower($key);
      // TODO: Make this if loop include the actions when tests are available.
      if (isset($old_entry[$key_lcase])) {
        if ($old_entry[$key_lcase]['count'] == 1) {
          $old_value = $old_entry[$key_lcase][0];
          $old_value_is_scalar = TRUE;
        }
        else {
          unset($old_entry[$key_lcase]['count']);
          $old_value = $old_entry[$key_lcase];
          $old_value_is_scalar = FALSE;
        }
      }

      // Identical multivalued attributes.
      if (is_array($new_val) && is_array($old_value) && count(array_diff($new_val, $old_value)) == 0) {
        unset($new_entry[$key]);
      }
      elseif ($old_value_is_scalar && !is_array($new_val) && Unicode::strtolower($old_value) == Unicode::strtolower($new_val)) {
        // Don't change values that aren't changing to avoid false permission
        // constraints.
        unset($new_entry[$key]);
      }
    }
    return $new_entry;
  }

  /**
   * Modify attributes of LDAP entry.
   *
   * @param string $dn
   *   DN of entry.
   * @param array $attributes
   *   Should follow the structure of ldap_add functions.
   *   Entry array: http://us.php.net/manual/en/function.ldap-add.php
   *     $attributes["attribute1"] = "value";
   *     $attributes["attribute2"][0] = "value1";
   *     $attributes["attribute2"][1] = "value2";.
   * @param bool|array $old_attributes
   *   Existing attributes.
   *
   * @return bool
   *   Result of query.
   */
  public function modifyLdapEntry($dn, array $attributes = [], $old_attributes = FALSE) {

    $this->connectAndBindIfNotAlready();

    if (!$old_attributes) {
      $result = @ldap_read($this->connection, $dn, 'objectClass=*');
      if (!$result) {
        \Drupal::logger('ldap_servers')->error(
          "LDAP Server ldap_read(%dn) in LdapServer::modifyLdapEntry() Error Server ID = %id, LDAP Err No: %ldap_errno LDAP Err Message: %ldap_err2str ", [
            '%dn' => $dn,
            '%id' => $this->id(),
            '%ldap_errno' => ldap_errno($this->connection),
            '%ldap_err2str' => ldap_err2str(ldap_errno($this->connection)),
          ]);
        return FALSE;
      }

      $entries = ldap_get_entries($this->connection, $result);
      if (is_array($entries) && $entries['count'] == 1) {
        $old_attributes = $entries[0];
      }
    }
    if (!empty($attributes['unicodePwd']) && $this->get('type') == 'ad') {
      $attributes['unicodePwd'] = $this->convertPasswordForActiveDirectoryunicodePwd($attributes['unicodePwd']);
    }

    $attributes = $this->removeUnchangedAttributes($attributes, $old_attributes);

    foreach ($attributes as $key => $cur_val) {
      $old_value = FALSE;
      $key_lcase = Unicode::strtolower($key);
      if (isset($old_attributes[$key_lcase])) {
        if ($old_attributes[$key_lcase]['count'] == 1) {
          $old_value = $old_attributes[$key_lcase][0];
        }
        else {
          unset($old_attributes[$key_lcase]['count']);
          $old_value = $old_attributes[$key_lcase];
        }
      }

      // Remove empty attributes.
      if ($cur_val == '' && $old_value != '') {
        unset($attributes[$key]);
        $result = @ldap_mod_del($this->connection, $dn, [$key_lcase => $old_value]);
        if (!$result) {
          \Drupal::logger('ldap_servers')->error(
            "LDAP Server ldap_mod_del(%dn) in LdapServer::modifyLdapEntry() Error Server ID = %id, LDAP Err No: %ldap_errno LDAP Err Message: %ldap_err2str ", [
              '%dn' => $dn,
              '%id' => $this->id(),
              '%ldap_errno' => ldap_errno($this->connection),
              '%ldap_err2str' => ldap_err2str(ldap_errno($this->connection)),
            ]);
          return FALSE;
        }
      }
      elseif (is_array($cur_val)) {
        foreach ($cur_val as $mv_key => $mv_cur_val) {
          if ($mv_cur_val == '') {
            // Remove empty values in multivalues attributes.
            unset($attributes[$key][$mv_key]);
          }
          else {
            $attributes[$key][$mv_key] = $mv_cur_val;
          }
        }
      }
    }

    if (count($attributes) > 0) {
      $result = @ldap_modify($this->connection, $dn, $attributes);
      if (!$result) {
        \Drupal::logger('ldap_servers')->error(
          "LDAP Server ldap_modify(%dn) in LdapServer::modifyLdapEntry() Error Server ID = %id, LDAP Err No: %ldap_errno LDAP Err Message: %ldap_err2str ", [
            '%dn' => $dn,
            '%id' => $this->id(),
            '%ldap_errno' => ldap_errno($this->connection),
            '%ldap_err2str' => ldap_err2str(ldap_errno($this->connection)),
          ]);
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
   * @param int $scope
   *   Scope of the search, defaults to subtree.
   *
   * @return array|bool
   *   An array of matching entries->attributes (will have 0 elements if search
   *   returns no results), or FALSE on error on any of the base DN queries.
   */
  public function searchAllBaseDns($filter, array $attributes = [], $scope = NULL) {
    if ($scope == NULL) {
      $scope = Server::SCOPE_SUBTREE;
    }
    $all_entries = [];

    foreach ($this->getBaseDn() as $base_dn) {
      $relative_filter = str_replace(',' . $base_dn, '', $filter);
      $entries = $this->search($base_dn, $relative_filter, $attributes, 0, 0, 0, NULL, $scope);
      // If error in any search, return false.
      if ($entries === FALSE) {
        return FALSE;
      }
      if (count($all_entries) == 0) {
        $all_entries = $entries;
      }
      else {
        $existing_count = $all_entries['count'];
        unset($entries['count']);
        foreach ($entries as $i => $entry) {
          $all_entries[$existing_count + $i] = $entry;
        }
        $all_entries['count'] = count($all_entries);
      }
    }

    return $all_entries;
  }

  // @codingStandardsIgnoreStart
  /**
   * Perform an LDAP search.
   *
   * @param string $base_dn
   *   The search base. If NULL, we use $this->basedn. should not be esacaped.
   * @param string $filter
   *   The search filter. such as sAMAccountName=jbarclay.  attribute values
   *   (e.g. jbarclay) should be esacaped before calling.
   * @param array $attributes
   *   List of desired attributes. If omitted, we only return "dn".
   * @param int $attrsonly
   *   Attributes.
   * @param int $sizelimit
   *   Size limit.
   * @param int $timelimit
   *   Time limit.
   * @param null $deref
   *   Dereference.
   * @param int $scope
   *   Scope.
   *
   * @return array|bool
   *   An array of matching entries->attributes (will have 0
   *   elements if search returns no results),
   *   or FALSE on error.
   *
   * @remaining params mimick ldap_search() function params
   * @TODO: Remove coding standard violation.
   */
  public function search($base_dn = NULL, $filter, array $attributes = [], $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = NULL, $scope = NULL) {
    // @codingStandardsIgnoreEnd
    if ($scope == NULL) {
      $scope = Server::SCOPE_SUBTREE;
    }
    if ($base_dn == NULL) {
      if (count($this->getBaseDn()) == 1) {
        $base_dn = $this->getBaseDn()[0];
      }
      else {
        return FALSE;
      }
    }

    if (\Drupal::config('ldap_help.settings')->get('watchdog_detail')) {
      \Drupal::logger('ldap_servers')->notice("LDAP search call with base_dn '%base_dn'. Filter is '%filter' with attributes '%attributes'. Only attributes %attrs_only, size limit %size_limit, time limit %time_limit, dereference %deref, scope %scope.", [
        '%base_dn' => $base_dn,
        '%filter' => $filter,
        '%attributes' => is_array($attributes) ? implode(',', $attributes) : 'none',
        '%attrs_only' => $attrsonly,
        '%size_limit' => $sizelimit,
        '%time_limit' => $timelimit,
        '%deref' => $deref ? $deref : 'null',
        '%scope' => $scope ? $scope : 'null',

      ]
      );
    }

    // When checking multiple servers, there's a chance we might not be
    // connected yet.
    if (!$this->connection) {
      $this->connect();
      $this->bind();
    }

    $ldap_query_params = [
      'connection' => $this->connection,
      'base_dn' => $base_dn,
      'filter' => $filter,
      'attributes' => $attributes,
      'attrsonly' => $attrsonly,
      'sizelimit' => $sizelimit,
      'timelimit' => $timelimit,
      'deref' => $deref,
      'scope' => $scope,
    ];

    if ($this->get('search_pagination')) {
      $aggregated_entries = $this->pagedLdapQuery($ldap_query_params);
      return $aggregated_entries;
    }
    else {
      $result = $this->ldapQuery($scope, $ldap_query_params);
      if ($result && ($this->countEntries($result) !== FALSE)) {
        $entries = ldap_get_entries($this->connection, $result);
        \Drupal::moduleHandler()->alter('ldap_server_search_results', $entries, $ldap_query_params);
        return (is_array($entries)) ? $entries : FALSE;
      }
      elseif ($this->hasError()) {
        \Drupal::logger('ldap_servers')->notice(
          "LDAP search error: %error. Context is base DN: %base_dn | filter: %filter| attributes: %attributes", [
            '%base_dn' => $ldap_query_params['base_dn'],
            '%filter' => $ldap_query_params['filter'],
            '%attributes' => json_encode($ldap_query_params['attributes']),
            '%error' => $this->formattedError($this->ldapErrorNumber()),
          ]
        );
        return FALSE;
      }
      else {
        return FALSE;
      }
    }
  }

  /**
   * Execute a paged LDAP query and return entries as one aggregated array.
   *
   * $this->searchPageStart and $this->searchPageEnd should be set before
   * calling if a particular set of pages is desired.
   *
   * @param resource $queryParameters
   *   Parameters of form: [
   *     'base_dn' => base_dn,
   *     'filter' =>  filter,
   *     'attributes' => attributes,
   *     'attrsonly' => attrsonly,
   *     'sizelimit' => sizelimit,
   *     'timelimit' => timelimit,
   *     'deref' => deref,
   *     'scope' => scope,
   *   ]
   *   This array of parameters is primarily passed on to ldapQuery() method.
   *
   * @return array|bool
   *   Array of LDAP entries or FALSE on error.
   */
  public function pagedLdapQuery($queryParameters) {
    if (!$this->get('search_pagination')) {
      \Drupal::logger('ldap_servers')
        ->error('Paged LDAP query functionality called but not enabled in LDAP server configuration.');
      return FALSE;
    }

    $paged_entries = [];
    $page_token = '';
    $page = 0;
    $estimated_entries = 0;
    $aggregated_entries = [];
    $aggregated_entries_count = 0;
    $has_page_results = FALSE;

    do {
      ldap_control_paged_result($this->connection, $this->get('search_page_size'), TRUE, $page_token);
      $result = $this->ldapQuery($queryParameters['scope'], $queryParameters);

      if ($page >= $this->searchPageStart) {
        $skipped_page = FALSE;
        if ($result && ($this->countEntries($result) !== FALSE)) {
          $page_entries = ldap_get_entries($this->connection, $result);
          unset($page_entries['count']);
          $has_page_results = (is_array($page_entries) && count($page_entries) > 0);
          $aggregated_entries = array_merge($aggregated_entries, $page_entries);
          $aggregated_entries_count = count($aggregated_entries);
        }
        elseif ($this->hasError()) {
          \Drupal::logger('ldap_servers')->notice(
            "LDAP search error: %error. Base DN: %base_dn | filter: %filter | attributes: %attributes.", [
              '%base_dn' => $queryParameters['base_dn'],
              '%filter' => $queryParameters['filter'],
              '%attributes' => json_encode($queryParameters['attributes']),
              '%error' => $this->formattedError($this->ldapErrorNumber()),
            ]);
          return FALSE;
        }
        else {
          return FALSE;
        }
      }
      else {
        $skipped_page = TRUE;
      }
      @ldap_control_paged_result_response($this->connection, $result, $page_token, $estimated_entries);
      if ($queryParameters['sizelimit'] && $this->ldapErrorNumber() == self::LDAP_SIZELIMIT_EXCEEDED) {
        // False positive error thrown. Do not set result limit error when
        // $sizelimit specified.
      }
      elseif ($this->hasError()) {
        \Drupal::logger('ldap_servers')->error('Paged query error: %error. Base DN: %base_dn | filter: %filter | attributes: %attributes.', [
          '%error' => $this->formattedError($this->ldapErrorNumber()),
          '%base_dn' => $queryParameters['base_dn'],
          '%filter' => $queryParameters['filter'],
          '%attributes' => json_encode($queryParameters['attributes']),
          '%query' => $queryParameters['query_display'],
        ]
        );
      }

      if (isset($queryParameters['sizelimit']) && $queryParameters['sizelimit'] && $aggregated_entries_count >= $queryParameters['sizelimit']) {
        $discarded_entries = array_splice($aggregated_entries, $queryParameters['sizelimit']);
        break;
      }
      // User defined pagination has run out.
      elseif ($this->searchPageEnd !== NULL && $page >= $this->searchPageEnd) {
        break;
      }
      // LDAP reference pagination has run out.
      elseif ($page_token === NULL || $page_token == '') {
        break;
      }
      $page++;
    } while ($skipped_page || $has_page_results);

    $aggregated_entries['count'] = count($aggregated_entries);
    return $aggregated_entries;
  }

  /**
   * Execute LDAP query and return LDAP records.
   *
   * @param int $scope
   *   Scope of search (base, subtree or one level).
   * @param array|resource $params
   *   See pagedLdapQuery() $params.
   *
   * @return resource|bool
   *   Array of LDAP entries.
   */
  public function ldapQuery($scope, array $params) {
    $result = FALSE;

    $this->connectAndBindIfNotAlready();

    switch ($scope) {
      case Server::SCOPE_SUBTREE:
        $result = @ldap_search($this->connection, $params['base_dn'], $params['filter'], $params['attributes'], $params['attrsonly'],
          $params['sizelimit'], $params['timelimit'], $params['deref']);
        if ($params['sizelimit'] && $this->ldapErrorNumber() == self::LDAP_SIZELIMIT_EXCEEDED) {
          // False positive error thrown.
          // Do not return result limit error when $sizelimit specified.
        }
        elseif ($this->hasError()) {
          \Drupal::logger('ldap_servers')->error('ldap_search() function error. LDAP Error: %message, ldap_search() parameters: %query', [
            '%message' => $this->formattedError($this->ldapErrorNumber()),
            '%query' => isset($params['query_display']) ? $params['query_display'] : NULL,
          ]
          );
        }
        break;

      case Server::SCOPE_BASE:
        $result = @ldap_read($this->connection, $params['base_dn'], $params['filter'], $params['attributes'], $params['attrsonly'],
          $params['sizelimit'], $params['timelimit'], $params['deref']);
        if ($params['sizelimit'] && $this->ldapErrorNumber() == self::LDAP_SIZELIMIT_EXCEEDED) {
          // False positive error thrown.
          // Do not result limit error when $sizelimit specified.
        }
        elseif ($this->hasError()) {
          \Drupal::logger('ldap_servers')->error('ldap_read() function error.  LDAP Error: %message, ldap_read() parameters: %query', [
            '%message' => $this->formattedError($this->ldapErrorNumber()),
            '%query' => @$params['query_display'],
          ]
          );
        }
        break;

      case Server::SCOPE_ONE_LEVEL:
        $result = @ldap_list($this->connection, $params['base_dn'], $params['filter'], $params['attributes'], $params['attrsonly'],
          $params['sizelimit'], $params['timelimit'], $params['deref']);
        if ($params['sizelimit'] && $this->ldapErrorNumber() == self::LDAP_SIZELIMIT_EXCEEDED) {
          // False positive error thrown.
          // Do not result limit error when $sizelimit specified.
        }
        elseif ($this->hasError()) {
          \Drupal::logger('ldap_servers')->error('ldap_list() function error. LDAP Error: %message, ldap_list() parameters: %query', [
            '%message' => $this->formattedError($this->ldapErrorNumber()),
            '%query' => $params['query_display'],
          ]
          );
        }
        break;
    }
    return $result;
  }

  /**
   * Convert DN array to lowercase.
   *
   * @param array $dns
   *   Mixed Case.
   *
   * @return array
   *   Lower Case.
   */
  public function dnArrayToLowerCase(array $dns) {
    return array_keys(array_change_key_case(array_flip($dns), CASE_LOWER));
  }

  /**
   * Fetch base DN.
   *
   * @return array
   *   All base DN.
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
    // Run the query as user 1.
      ->addMetaData('account', \Drupal::entityManager()->getStorage('user')->load(1));

    $result = $query->execute();

    if (!empty($result)) {
      if (count($result) == 1) {
        return User::load(array_values($result)[0]);
      }
      else {
        $uids = implode(',', $result);
        \Drupal::logger('ldap_servers')->error(
          'Multiple users (uids: %uids) with same puid (puid=%puid, sid=%sid, ldap_user_puid_property=%ldap_user_puid_property)', [
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
   * @param array $ldap_entry
   *   The LDAP entry.
   *
   * @return string
   *   The user name.
   */
  public function userUsernameFromLdapEntry(array $ldap_entry) {

    if ($this->get('account_name_attr')) {
      $accountName = (empty($ldap_entry[$this->get('account_name_attr')][0])) ? FALSE : $ldap_entry[$this->get('account_name_attr')][0];
    }
    elseif ($this->get('user_attr')) {
      $accountName = (empty($ldap_entry[$this->get('user_attr')][0])) ? FALSE : $ldap_entry[$this->get('user_attr')][0];
    }
    else {
      $accountName = FALSE;
    }

    return $accountName;
  }

  /**
   * Returns the user's email from the LDAP entry.
   *
   * @param array $ldap_entry
   *   The LDAP entry.
   *
   * @return string|bool
   *   The user's mail value or FALSE if none present.
   */
  public function userEmailFromLdapEntry(array $ldap_entry) {

    // Not using template.
    if ($ldap_entry && $this->get('mail_attr') && isset($ldap_entry[$this->get('mail_attr')][0])) {
      $mail = isset($ldap_entry[$this->get('mail_attr')][0]) ? $ldap_entry[$this->get('mail_attr')][0] : FALSE;
      return $mail;
    }
    // Template is of form [cn]@illinois.edu.
    elseif ($ldap_entry && $this->get('mail_template')) {
      $tokenHelper = new TokenProcessor();
      return $tokenHelper->tokenReplace($ldap_entry, $this->get('mail_template'), 'ldap_entry');
    }
    else {
      return FALSE;
    }
  }

  /**
   * Fetches the persistent UID from the LDAP entry.
   *
   * @param array $ldap_entry
   *   The LDAP entry.
   *
   * @return string
   *   The user's PUID or permanent user id (within ldap), converted from
   *   binary, if applicable.
   */
  public function userPuidFromLdapEntry(array $ldap_entry) {
    if ($this->get('unique_persistent_attr') && isset($ldap_entry[Unicode::strtolower($this->get('unique_persistent_attr'))])) {
      $puid = $ldap_entry[Unicode::strtolower($this->get('unique_persistent_attr'))];
      // If its still an array...
      if (is_array($puid)) {
        $puid = $puid[0];
      }
      return ($this->get('unique_persistent_attr_binary')) ? TokenProcessor::binaryConversionToString($puid) : $puid;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Undocumented.
   *
   * TODO: Naming and scope are unclear. Restructure if possible.
   *
   * @param \Drupal\user\Entity\User|array|mixed $user
   *   User account or name.
   *
   * @return array|bool
   *   User's LDAP entry.
   */
  public function userUserToExistingLdapEntry($user) {
    $userLdapEntry = FALSE;

    if (is_object($user)) {
      $userLdapEntry = $this->matchUsernameToExistingLdapEntry($user->getAccountName());
    }
    elseif (is_array($user)) {
      $userLdapEntry = $user;
    }
    elseif (is_scalar($user)) {
      // Username.
      if (strpos($user, '=') === FALSE) {
        $userLdapEntry = $this->matchUsernameToExistingLdapEntry($user);
      }
      else {
        $userLdapEntry = $this->dnExists($user, 'ldap_entry');
      }
    }
    return $userLdapEntry;
  }

  /**
   * Queries LDAP server for the user.
   *
   * @param string $drupaUsername
   *   Drupal user name.
   *
   * @return array|bool
   *   An associative array representing LDAP data of a user. For example:
   *   'sid' => LDAP server id
   *   'mail' => derived from LDAP mail (not always populated).
   *   'dn'   => dn of user
   *   'attr' => single LDAP entry array in form returned from ldap_search()
   *   'dn' => dn of entry
   */
  public function matchUsernameToExistingLdapEntry($drupaUsername) {

    foreach ($this->getBaseDn() as $baseDn) {

      if (empty($baseDn)) {
        continue;
      }

      $massager = new MassageAttributes();
      $filter = '(' . $this->get('user_attr') . '=' . $massager->queryLdapAttributeValue($drupaUsername) . ')';

      $result = $this->search($baseDn, $filter);
      if (!$result || !isset($result['count']) || !$result['count']) {
        continue;
      }

      // Must find exactly one user for authentication to work.
      if ($result['count'] != 1) {
        $count = $result['count'];
        \Drupal::logger('ldap_servers')->error('Error: %count users found with %filter under %base_dn.', [
          '%count' => $count,
          '%filter' => $filter,
          '%base_dn' => $baseDn,
        ]
          );
        continue;
      }
      $match = $result[0];
      // These lines serve to fix the attribute name in case a
      // naughty server (i.e.: MS Active Directory) is messing the
      // characters' case.
      // This was contributed by Dan "Gribnif" Wilga, and described
      // here: http://drupal.org/node/87833
      $name_attr = $this->get('user_attr');

      if (isset($match[$name_attr][0])) {
        // Leave name.
      }
      elseif (isset($match[Unicode::strtolower($name_attr)][0])) {
        $name_attr = Unicode::strtolower($name_attr);
      }
      else {
        if ($this->get('bind_method') == 'anon_user') {
          $result = [
            'dn' => $match['dn'],
            'mail' => $this->userEmailFromLdapEntry($match),
            'attr' => $match,
            'id' => $this->id(),
          ];
          return $result;
        }
        else {
          continue;
        }
      }

      // Finally, we must filter out results with spaces added before
      // or after, which are considered OK by LDAP but are no good for us
      // We allow lettercase independence, as requested by Marc Galera
      // on http://drupal.org/node/97728
      //
      // Some setups have multiple $name_attr per entry, as pointed out by
      // Clarence "sparr" Risher on http://drupal.org/node/102008, so we
      // loop through all possible options.
      foreach ($match[$name_attr] as $value) {
        if (Unicode::strtolower(trim($value)) == Unicode::strtolower($drupaUsername)) {
          $result = [
            'dn' => $match['dn'],
            'mail' => $this->userEmailFromLdapEntry($match),
            'attr' => $match,
            'id' => $this->id(),
          ];
          return $result;
        }
      }
    }
  }

  /**
   * Is a user a member of group?
   *
   * @param string $group_dn
   *   Group DN in mixed case.
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user  or a username.
   * @param bool $nested
   *   TRUE, or FALSE indicating to test for nested groups, by default set
   *   to NULL.
   *
   * @return bool
   *   Whether the user belongs to the group.
   */
  public function groupIsMember($group_dn, $user, $nested = NULL) {

    $nested = ($nested === TRUE || $nested === FALSE) ? $nested : $this->groupNested();
    $group_dns = $this->groupMembershipsFromUser($user, $nested);
    // While list of group dns is going to be in correct mixed case, $group_dn
    // may not since it may be derived from user entered values so make sure
    // in_array() is case insensitive.
    return (is_array($group_dns) && in_array(Unicode::strtolower($group_dn), $this->dnArrayToLowerCase($group_dns)));
  }

  /**
   * Recurse through all child groups and add members.
   *
   * @param array $current_member_entries
   *   Entries of LDAP group entries that are starting point. Should include at
   *   least 1 entry.
   * @param array $all_member_dns
   *   All member DN as an array of all groups the user is a member of. Mixed
   *   case values.
   * @param array $tested_group_ids
   *   Tested group IDs as an array array of tested group dn, cn, uid, etc.
   *   Mixed case values. Whether these value are dn, cn, uid, etc depends on
   *   what attribute members, uniquemember, memberUid contains whatever
   *   attribute is in $this->$tested_group_ids to avoid redundant recursion.
   * @param int $level
   *   Current level of recursion.
   * @param int $max_levels
   *   Maximum number of recursion levels allowed.
   * @param bool|array $object_classes
   *   Undocumented.
   *
   * @return bool
   *   If operation was successful.
   */
  public function groupMembersRecursive(array $current_member_entries, array &$all_member_dns, array &$tested_group_ids, $level, $max_levels, $object_classes = FALSE) {

    if (!$this->groupGroupEntryMembershipsConfigured() || !is_array($current_member_entries) || count($current_member_entries) == 0) {
      return FALSE;
    }
    if (isset($current_member_entries['count'])) {
      unset($current_member_entries['count']);
    }

    foreach ($current_member_entries as $member_entry) {
      // 1.  Add entry itself if of the correct type to $all_member_dns.
      $objectClassMatch = (!$object_classes || (count(array_intersect(array_values($member_entry['objectclass']), $object_classes)) > 0));
      $objectIsGroup = in_array($this->groupObjectClass(), array_values($member_entry['objectclass']));
      // Add member.
      if ($objectClassMatch && !in_array($member_entry['dn'], $all_member_dns)) {
        $all_member_dns[] = $member_entry['dn'];
      }

      // 2. If its a group, keep recurse the group for descendants.
      if ($objectIsGroup && $level < $max_levels) {
        if ($this->groupMembershipsAttrMatchingUserAttr() == 'dn') {
          $group_id = $member_entry['dn'];
        }
        else {
          $group_id = $member_entry[$this->groupMembershipsAttrMatchingUserAttr()][0];
        }
        // 3. skip any groups that have already been tested.
        if (!in_array($group_id, $tested_group_ids)) {
          $tested_group_ids[] = $group_id;
          $member_ids = $member_entry[$this->groupMembershipsAttr()];
          if (isset($member_ids['count'])) {
            unset($member_ids['count']);
          }
          $ors = [];
          foreach ($member_ids as $key => $member_id) {
            // @todo this would be replaced by query template
            $ors[] = $this->groupMembershipsAttr() . '=' . self::ldapEscape($member_id);
          }

          if (count($ors)) {
            // Example 1: (|(cn=group1)(cn=group2))
            // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
            $query_for_child_members = '(|(' . implode(")(", $ors) . '))';
            // Add or on object classes, otherwise get all object classes.
            if (count($object_classes)) {
              $object_classes_ors = ['(objectClass=' . $this->groupObjectClass() . ')'];
              foreach ($object_classes as $object_class) {
                $object_classes_ors[] = '(objectClass=' . $object_class . ')';
              }
              $query_for_child_members = '&(|' . implode($object_classes_ors) . ')(' . $query_for_child_members . ')';
            }
            // Need to search on all basedns one at a time.
            foreach ($this->getBaseDn() as $base_dn) {
              $child_member_entries = $this->search(
                $base_dn,
                $query_for_child_members,
                [
                  'objectclass',
                  $this->groupMembershipsAttr(),
                  $this->groupMembershipsAttrMatchingUserAttr(),
                ]
              );
              if ($child_member_entries !== FALSE) {
                $this->groupMembersRecursive($child_member_entries, $all_member_dns, $tested_group_ids, $level + 1, $max_levels, $object_classes);
              }
            }
          }
        }
      }
    }
  }

  /**
   * Get list of all groups that a user is a member of.
   *
   * If $nested is TRUE, the list will include all parent groups. For example,
   * if the user is a member of the "programmer" group and the "programmer"
   * group is a member of the "it" group, the user is a member of both the
   * "programmer" and the "it" group. If $nested is FALSE, the list will only
   * include groups which are directly assigned to the user.
   *
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user  or a username.
   * @param bool $nested
   *   This is configurable as a convenience to ServerTestForm.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   */
  public function groupMembershipsFromUser($user, $nested = NULL) {

    $group_dns = FALSE;
    $user_ldap_entry = @$this->userUserToExistingLdapEntry($user);
    if (!$user_ldap_entry || $this->groupFunctionalityUnused()) {
      return FALSE;
    }
    if ($nested === NULL) {
      $nested = $this->groupNested();
    }

    // Preferred method.
    if ($this->groupUserMembershipsFromAttributeConfigured()) {
      $group_dns = $this->groupUserMembershipsFromUserAttr($user_ldap_entry, $nested);
    }
    elseif ($this->groupGroupEntryMembershipsConfigured()) {
      $group_dns = $this->groupUserMembershipsFromEntry($user_ldap_entry, $nested);
    }
    return $group_dns;

  }

  /**
   * Get list of groups that a user is a member of using the memberOf attribute.
   *
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user  or a username.
   * @param bool $nested
   *   If groups should be checked recursively, or not.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   *
   * @see groupMembershipsFromUser()
   */
  public function groupUserMembershipsFromUserAttr($user, $nested = NULL) {
    if (!$this->groupUserMembershipsFromAttributeConfigured()) {
      return FALSE;
    }
    if ($nested === NULL) {
      $nested = $this->groupNested();
    }

    $groupAttribute = $this->groupUserMembershipsAttr();

    $not_user_ldap_entry = empty($user['attr'][$groupAttribute]);
    // If Drupal user passed in, try to get user_ldap_entry.
    if ($not_user_ldap_entry) {
      $user = $this->userUserToExistingLdapEntry($user);
      $not_user_ldap_entry = empty($user['attr'][$groupAttribute]);
      if ($not_user_ldap_entry) {
        // User's membership attribute is not present. E either misconfigured or
        // the query failed.
        return FALSE;
      }
    }
    // If not exited yet, $user must be user_ldap_entry.
    $user_ldap_entry = $user;
    $all_group_dns = [];
    $tested_group_ids = [];
    $level = 0;

    $member_group_dns = $user_ldap_entry['attr'][$groupAttribute];
    if (isset($member_group_dns['count'])) {
      unset($member_group_dns['count']);
    }
    $ors = [];
    foreach ($member_group_dns as $i => $member_group_dn) {
      $all_group_dns[] = $member_group_dn;
      if ($nested) {
        if ($this->groupMembershipsAttrMatchingUserAttr() == 'dn') {
          $member_value = $member_group_dn;
        }
        else {
          $member_value = $this->getFirstRdnValueFromDn($member_group_dn, $this->groupMembershipsAttrMatchingUserAttr());
        }
        $ors[] = $this->groupMembershipsAttr() . '=' . self::ldapEscape($member_value);
      }
    }

    if ($nested && count($ors)) {
      // Only 50 or so per query.
      for ($i = 0; $i < count($ors); $i = $i + self::LDAP_SERVER_LDAP_QUERY_CHUNK) {
        $current_ors = array_slice($ors, $i, self::LDAP_SERVER_LDAP_QUERY_CHUNK);
        // Example 1: (|(cn=group1)(cn=group2))
        // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
        $or = '(|(' . implode(")(", $current_ors) . '))';
        $query_for_parent_groups = '(&(objectClass=' . $this->groupObjectClass() . ')' . $or . ')';

        // Need to search on all base DN one at a time.
        foreach ($this->getBaseDn() as $base_dn) {
          // No attributes, just dns needed.
          $group_entries = $this->search($base_dn, $query_for_parent_groups);
          if ($group_entries !== FALSE && $level < self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT) {
            $this->groupMembershipsFromEntryResursive($group_entries, $all_group_dns, $tested_group_ids, $level + 1, self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT);
          }
        }
      }
    }

    return $all_group_dns;
  }

  /**
   * Get list of all groups that a user is a member of by querying groups.
   *
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user or a username.
   * @param bool $nested
   *   If groups should be checked recursively, or not.
   *
   * @return array|false
   *   Array of group dns in mixed case or FALSE on error.
   *
   * @see groupMembershipsFromUser()
   */
  public function groupUserMembershipsFromEntry($user, $nested = NULL) {
    if (!$this->groupGroupEntryMembershipsConfigured()) {
      return FALSE;
    }
    if ($nested === NULL) {
      $nested = $this->groupNested();
    }

    $userLdapEntry = $this->userUserToExistingLdapEntry($user);

    // MIXED CASE VALUES.
    $all_group_dns = [];
    // Array of dns already tested to avoid excess queries MIXED CASE VALUES.
    $tested_group_ids = [];
    $level = 0;

    if ($this->groupMembershipsAttrMatchingUserAttr() == 'dn') {
      $member_value = $userLdapEntry['dn'];
    }
    else {
      $member_value = $userLdapEntry['attr'][$this->groupMembershipsAttrMatchingUserAttr()][0];
    }

    $group_query = '(&(objectClass=' . $this->groupObjectClass() . ')(' . $this->groupMembershipsAttr() . "=$member_value))";

    // Need to search on all basedns one at a time.
    foreach ($this->getBaseDn() as $base_dn) {
      // Only need dn, so empty array forces return of no attributes.
      $group_entries = $this->search($base_dn, $group_query, []);
      if ($group_entries !== FALSE) {
        $max_levels = ($nested) ? self::LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT : 0;
        $this->groupMembershipsFromEntryResursive($group_entries, $all_group_dns, $tested_group_ids, $level, $max_levels);
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
   */
  public function groupMembershipsFromEntryResursive(array $current_group_entries, array &$all_group_dns, array &$tested_group_ids, $level, $max_levels) {

    if (!$this->groupGroupEntryMembershipsConfigured() || !is_array($current_group_entries) || count($current_group_entries) == 0) {
      return FALSE;
    }
    if (isset($current_group_entries['count'])) {
      unset($current_group_entries['count']);
    }

    $ors = [];
    foreach ($current_group_entries as $i => $group_entry) {
      if ($this->groupMembershipsAttrMatchingUserAttr() == 'dn') {
        $member_id = $group_entry['dn'];
      }
      // Maybe cn, uid, etc is held.
      else {
        $member_id = $this->getFirstRdnValueFromDn($group_entry['dn'], $this->groupMembershipsAttrMatchingUserAttr());
      }

      if ($member_id && !in_array($member_id, $tested_group_ids)) {
        $tested_group_ids[] = $member_id;
        $all_group_dns[] = $group_entry['dn'];
        // Add $group_id (dn, cn, uid) to query.
        $ors[] = $this->groupMembershipsAttr() . '=' . self::ldapEscape($member_id);
      }
    }

    if (count($ors)) {
      $count = count($ors);
      // Only 50 or so per query.
      for ($i = 0; $i < $count; $i = $i + self::LDAP_SERVER_LDAP_QUERY_CHUNK) {
        $current_ors = array_slice($ors, $i, self::LDAP_SERVER_LDAP_QUERY_CHUNK);
        // Example 1: (|(cn=group1)(cn=group2))
        // Example 2: (|(dn=cn=group1,ou=blah...)(dn=cn=group2,ou=blah...))
        $or = '(|(' . implode(")(", $current_ors) . '))';
        $query_for_parent_groups = '(&(objectClass=' . $this->groupObjectClass() . ')' . $or . ')';

        // Need to search on all basedns one at a time.
        foreach ($this->getBaseDn() as $base_dn) {
          // No attributes, just dns needed.
          $group_entries = $this->search($base_dn, $query_for_parent_groups);
          if ($group_entries !== FALSE && $level < $max_levels) {
            $this->groupMembershipsFromEntryResursive($group_entries, $all_group_dns, $tested_group_ids, $level + 1, $max_levels);
          }
        }
      }
    }

    return TRUE;
  }

  /**
   * Get "groups" from derived from DN.  Has limited usefulness.
   *
   * @param mixed $user
   *   A Drupal user entity, an LDAP entry array of a user or a username.
   *
   * @return array|bool
   *   Array of group strings.
   */
  public function groupUserMembershipsFromDn($user) {

    if (!$this->groupDeriveFromDn() || !$this->groupDeriveFromDnAttr()) {
      return FALSE;
    }
    elseif ($user_ldap_entry = $this->userUserToExistingLdapEntry($user)) {
      return $this->getAllRdnValuesFromDn($user_ldap_entry['dn'], $this->groupDeriveFromDnAttr());
    }
    else {
      return FALSE;
    }

  }

  /**
   * Does the LDAP query return an error.
   *
   * @return bool
   *   Error state.
   */
  public function hasError() {
    if ($this->ldapErrorNumber() != Server::LDAP_SUCCESS) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Returns a string for the error to show administrators and in logs.
   *
   * @param int $number
   *   The LDAP error number.
   *
   * @return string
   *   Human readable string with error number.
   */
  public function formattedError($number) {
    return ldap_err2str($number) . ' (' . $number . ')';
  }

  /**
   * Returns the raw LDAP error code.
   */
  public function ldapErrorNumber() {
    return ldap_errno($this->connection);
  }

  /**
   * Returns whether groups are in use.
   */
  protected function groupFunctionalityUnused() {
    return $this->get('grp_unused');
  }

  /**
   * Returns whether groups are nested.
   */
  protected function groupNested() {
    return $this->get('grp_nested');
  }

  /**
   * Returns entity configuration value.
   */
  protected function groupUserMembershipsAttrExists() {
    return $this->get('grp_user_memb_attr_exists');
  }

  /**
   * Returns entity configuration value.
   */
  protected function groupUserMembershipsAttr() {
    return $this->get('grp_user_memb_attr');
  }

  /**
   * Returns entity configuration value.
   */
  protected function groupMembershipsAttrMatchingUserAttr() {
    return $this->get('grp_memb_attr_match_user_attr');
  }

  /**
   * Returns entity configuration value.
   */
  public function groupMembershipsAttr() {
    return $this->get('grp_memb_attr');
  }

  /**
   * Returns entity configuration value.
   */
  public function groupObjectClass() {
    return $this->get('grp_object_cat');
  }

  /**
   * Returns entity configuration value.
   */
  protected function groupDeriveFromDn() {
    return $this->get('grp_derive_from_dn');
  }

  /**
   * Returns entity configuration value.
   */
  protected function groupDeriveFromDnAttr() {
    return $this->get('grp_derive_from_dn_attr');
  }

  /**
   * Check if group memberships from attribute are configured.
   *
   * @return bool
   *   Whether group user memberships are configured.
   */
  public function groupUserMembershipsFromAttributeConfigured() {
    return $this->groupUserMembershipsAttrExists() && $this->groupUserMembershipsAttr();
  }

  /**
   * Check if group memberships from group entry are configured.
   *
   * @return bool
   *   Whether group memberships from group entry are configured.
   */
  public function groupGroupEntryMembershipsConfigured() {
    return $this->groupMembershipsAttrMatchingUserAttr() && $this->groupMembershipsAttr();
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
    $rdn = Unicode::strtolower($rdn);
    $rdn_value = FALSE;
    foreach ($pairs as $p) {
      $pair = explode('=', $p);
      if (Unicode::strtolower(trim($pair[0])) == $rdn) {
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
    $rdn = Unicode::strtolower($rdn);
    $rdn_values = [];
    foreach ($pairs as $p) {
      $pair = explode('=', $p);
      if (Unicode::strtolower(trim($pair[0])) == $rdn) {
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
  public function ldapExplodeDn($dn, $attribute) {
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

}
