<?php

/**
 * @file
 * Test script functions for testing ldap functionality outside of Drupal.
 */

error_reporting(E_ALL | E_STRICT);
set_time_limit(0);
ini_set("display_errors", 1);
ini_set("max_execution_time", 0);

define('LDAP_SERVERS_BIND_METHOD_SERVICE_ACCT', 1);
define('LDAP_SERVERS_BIND_METHOD_ANON', 3);


class ProtocolPlaceholder implements \Drupal\ldap_servers\LdapProtocol {
  // This is a workaround for removing redundant definitions.
}

// error_reporting(E_ALL  &  ~E_NOTICE);.
define('LDAP_SCRIPTS_COMMAND_LINE_WARNING', "Warning: PHP from the command line may have different PHP versions, php.ini files, and security context than running in a webserver context. This may produce false test results since Drupal LDAP Modules are run in the web server context.");

require_once 'config.inc';

/**
 *
 */
function ldap_help_connect($address, $port, $tls, $test = FALSE) {
  $protocol = new ProtocolPlaceholder();

  if ($test) {
    // Test for ldap extensions that don't actually connect until bind.
    $false_con = ldap_connect("fakehostname.sdfserewerdfsdf.com", 389);
    if (ldap_errno($false_con) == $protocol::LDAP_SUCCESS) {
      $con = ldap_connect($address, $port);
      return array($protocol::LDAP_OTHER, "ldap_connect does not actually connect until bind with installed extension, so connect is not a valid test.", $con);
    }
  }

  $con = ldap_connect($address, $port);

  if (!$con || ldap_errno($con) != $protocol::LDAP_SUCCESS) {
    $err = ldap_errno($con) . ":" . ldap_error($con) . ":" . ldap_err2str(ldap_errno($con)) . "!";
    return array($protocol::LDAP_CONNECT_ERROR, "LDAP Connect failure to  $address : $port. $err");
  }

  // Use TLS if we are configured and able to.
  if ($tls) {
    ldap_get_option($con, LDAP_OPT_PROTOCOL_VERSION, $vers);
    if ($vers == -1) {
      return array($protocol::LDAP_PROTOCOL_ERROR, "Could not get LDAP protocol version.");
    }
    if ($vers != 3) {
      return array($protocol::LDAP_CONNECT_ERROR, 'Could not start TLS, only supported by LDAP v3.');
    }
    elseif (!function_exists('ldap_start_tls')) {
      return array($protocol::LDAP_CONNECT_ERROR, 'Could not start TLS. It does not seem to be supported by this PHP setup.');
    }
    elseif (!ldap_start_tls($con)) {
      return array($protocol::LDAP_CONNECT_ERROR, "Could not start TLS. (Error " . ldap_errno($con) . ":" . ldap_error($con) . ").");
    }
  }

  return array($protocol::LDAP_SUCCESS, "Successful Connection!", $con);
}

/**
 *
 */
function ldap_help_show_error($con) {
  return "\nLDAP Error Number: " . ldap_errno($con) . "\nLDAP Error Description: " . ldap_error($con);
}

/**
 *
 */
function ldap_help_display($title, $value = NULL) {
  if (is_array($value)) {
    echo "\n" . $title;
    foreach ($title as $subtitle => $subvalue) {
      ldap_help_display($subtitle, $subvalue);
    }
  }
  if (!$title && $value) {
    echo "\n" . $value;
  }
  elseif ((int) $title === $title) {
    echo "\n" . $value;
  }
  else {
    echo "\n" . "$title: $value";
  }

}

/**
 * Disconnect (unbind) from an active LDAP server.
 */
function ldap_help_disconnect(&$con) {
  if (!$con) {
    // Never bound or not currently bound, so no need to disconnect.
  }
  else {
    ldap_help_disconnect($con);
    $con = NULL;
  }
}

/**
 * Parse php modules from phpinfo .*/
function ldap_help_parsePHPModules() {
  ob_start();
  phpinfo(INFO_MODULES);
  $s = ob_get_contents();
  ob_end_clean();
  $matches = array();
  preg_match_all("/(\nLDAP Support.*Vendor Version[^\n]*?).*$/iDsU", $s, $matches);
  return isset($matches[1][0]) ? "\nphpinfo() LDAP Info:" . $matches[1][0] : '';
}

/**
 *
 */
function ldap_help_encodePassword($password) {
  $password = "\"" . $password . "\"";
  $encoded = "";
  for ($i = 0; $i < strlen($password); $i++) {
    $encoded .= "{$password{$i}}\000";
  }
  return $encoded;
}
