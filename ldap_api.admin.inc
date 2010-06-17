<?php
// $Id$

/**
 * @file
 * Administrative page callbacks for the ldap_api module.
 */

/**
 * Implements the settings page.
 *
 * @return
 *   The form structure.
 */
function ldap_api_info() {
  drupal_add_css(drupal_get_path('module', 'system') .'/system.css', 'module', 'all', FALSE);
  include_once(drupal_get_path('module', 'system') .'/system.admin.inc');

  $data = _ldap_api_get_ldap_settings();

  foreach($data as $title => $value) {
    if (! is_array($value)) {
      $status[] = array('title' => $title, 'value' => $value);
    }
  }
  return theme_status_report($status);
}

function ldap_api_list_servers() {
  return drupal_get_form('ldap_api_list_servers_form');
}

/**
 * Implements the LDAP servers list.
 *
 * @return
 *   The HTML table with the servers list.
 */
function ldap_api_list_servers_form() {
  $form['list'] = array();
  $result = db_query("SELECT sid, name, active, weight FROM {ldap_servers} ORDER BY weight");
  while ($row = db_fetch_object($result)) {
    $form['list'][$row->sid] = array(
      'name' => array('#value' => $row->name),
      'active' => array('#value' => $row->active),
      'weight' => array(
        '#type' => 'weight',
        '#name' => 'sid_'. $row->sid .'_weight',
        '#delta' => 10,
        '#default_value' => $row->weight,
      ),
    );
  }

  $form['submit'] = array(
    '#type'  => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}

/**
 * Submit hook for the servers list form.
 */
function ldap_api_list_servers_submit($form, &$form_state) {
  $op = $form_state['clicked_button']['#value'];
  switch ($op) {
    case t('Save'):
      foreach ($form_state['clicked_button']['#post'] as $name => $val) {
        if (preg_match('/^sid_.*_weight/', $name)) {
          $sid = preg_replace(array('/^sid_/', '/_weight$/'), array('', ''), $name);
          db_query("UPDATE {ldap_servers} SET weight = %d WHERE sid = %d", $val, $sid);
        }
      }
      break;
  }
}

/**
 * Implements the LDAP server edit page.
 *
 * @param $form_state
 *   A form state array.
 * @param $op
 *   An operatin - add or edit.
 * @param $sid
 *   A LDAP server ID.
 *
 * @return
 *   The form structure.
 */
function ldap_api_edit_server(&$form_state, $op = NULL, $sid = NULL) {
  drupal_add_js(drupal_get_path('module', 'ldap_api') .'/ldap_api.admin.js');

  if ($op == "edit" && $sid) {
    $edit = db_fetch_array(db_query("SELECT * FROM {ldap_servers} WHERE sid = %d", $sid));
    $form['sid'] = array(
      '#type' => 'hidden',
      '#value' => $sid,
    );
  }
  else {
    $edit = array(
      'name' => '',
      'address' => '',
      'port' => '389',
      'tls' => 0,
      'basedn' => '',
      'binddn' => '',
      'bindpw' => FALSE,
    );
  }

  $form['server-settings'] = array(
    '#type' => 'fieldset',
    '#title' => t('Server settings'),
    '#collapsible' => TRUE,
    '#collapsed' => FALSE,
  );
  $form['server-settings']['name'] = array(
    '#type' => 'textfield',
    '#title' => t('Name'),
    '#default_value' => $edit['name'],
    '#description' => t('Choose a <em><strong>unique</strong></em> name for this server configuration.'),
    '#size' => 50,
    '#maxlength' => 255,
    '#required' => TRUE,
  );
  $form['server-settings']['server'] = array(
    '#type' => 'textfield',
    '#title' => t('LDAP server'),
    '#default_value' => $edit['server'],
    '#size' => 50,
    '#maxlength' => 255,
    '#description' => t('The domain name or IP address of your LDAP Server.'),
    '#required' => TRUE,
  );
  $form['server-settings']['port'] = array(
    '#type' => 'textfield',
    '#title' => t('LDAP port'),
    '#default_value' => $edit['port'],
    '#size' => 5,
    '#maxlength' => 5,
    '#description' => t('The TCP/IP port on the above server which accepts LDAP connections. Must be an integer.'),
  );
  $form['server-settings']['tls'] = array(
    '#type' => 'checkbox',
    '#title' => t('Use Start-TLS'),
    '#default_value' => $edit['tls'],
    '#description' => t('Secure the connection between the Drupal and the LDAP servers using TLS.<br /><em>Note: To use START-TLS, you must set the LDAP Port to 389.</em>'),
  );
  $form['login-procedure'] = array(
    '#type' => 'fieldset',
    '#title' => t('Login procedure'),
    '#collapsible' => TRUE,
    '#collapsed' => FALSE,
  );
  $form['login-procedure']['basedn'] = array(
    '#type' => 'textarea',
    '#title' => t('Base DNs'),
    '#default_value' => $edit['basedn'],
    '#cols' => 50,
    '#rows' => 6,
    '#description' => t('Base DNs for users. Enter one per line in case you need several of them.'),
  );
  $form['advanced'] = array(
    '#type' => 'fieldset',
    '#title' => t('Advanced configuration'),
    '#description' => t('<p>The process of authentication starts by establishing an anonymous connection to the LDAP directory and looking up for the user on it. Once this user is found, LDAP authentication is performed on them.</p><p>However, some LDAP configurations (specially common in <strong>Active Directory</strong> setups) restrict anonymous searches.</p><p>If your LDAP setup does not allow anonymous searches, or these are restricted in such a way that login names for users cannot be retrieved as a result of them, then you have to specify here a DN//password pair that will be used for these searches.</p><p>For security reasons, this pair should belong to an LDAP account with stripped down permissions.</p>'),
    '#collapsible' => TRUE,
    '#collapsed' => FALSE,
  );
  if (!$edit['bindpw']) {
    $form['advanced']['binddn'] =  array(
      '#type' => 'textfield',
      '#title' => t('DN for non-anonymous search'),
      '#default_value' => $edit['binddn'],
      '#size' => 50,
      '#maxlength' => 255,
    );
    $form['advanced']['bindpw'] = array(
      '#type' => 'password',
      '#title' => t('Password for non-anonymous search'),
      '#size' => 12,
      '#maxlength' => 255,
    );
  }
  else {
    $form['advanced']['binddn'] =  array(
      '#type' => 'item',
      '#title' => t('DN for non-anonymous search'),
      '#value' => $edit['binddn'],
    );
    // Give an option to clear the password.
    $form['advanced']['bindpw_clear'] = array(
      '#type' => 'checkbox',
      '#title' => t('Clear current password and change DN'),
      '#default_value' => FALSE,
    );
  }
  $form['advanced']['test'] = array(
    '#type'  => 'submit',
    '#value' => t('Test'),
    '#suffix' => '<div id="test-spinner" style="display: none;">'. theme_image(drupal_get_path('module', 'ldap_api') .'/images/spinner.gif') .'</div><div id="test-message" class="messages" style="display: none;"></div>',
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save configuration'),
  );

  return $form;
}

/**
 * Validate hook for the LDAP server form.
 */
function ldap_api_server_validate($form, &$form_state) {
  $values = $form_state['values'];

  if (!isset($values['sid'])) {
    if (db_fetch_object(db_query("SELECT name FROM {ldap_servers} WHERE name = '%s'", $values['name']))) {
      form_set_error('name', t('An LDAP server with that name already exists.'));
    }
  }
  if (!is_numeric($values['port'])) {
    form_set_error('port', t('The TCP/IP port must be an integer.'));
  }
}

/**
 * Submit hook for the LDAP server form.
 */
function ldap_api_server_submit($form, &$form_state) {
  $op = $form_state['clicked_button']['#value'];
  $values = $form_state['values'];
  switch ($op) {
    case t('Save configuration'):
      if (!isset($values['sid'])) {
         db_query("INSERT INTO {ldap_servers} (name, address, port, tls, basedn, binddn, bindpw, active) VALUES ('%s', %d, '%s', %d, %d, %d, '%s', '%s', '%s', '%s', '%s', '%s', '%s')", $values['name'], 1, $values['server'], $values['port'], $values['tls'], $values['enc_type'], $values['basedn'], trim($values['user_attr']), trim($values['mail_attr']), $values['binddn'], $values['bindpw'], trim($values['login_php']), trim($values['filter_php']));
        drupal_set_message(t('LDAP server %name has been added.', array('%name' => $values['name'])));
        watchdog('ldap_api', 'LDAP server %name has been added.', array('%name' => $values['name']));
      }
      else {
        if (isset($values['bindpw_clear'])) {
          db_query("UPDATE {ldap_servers} SET name = '%s', address = '%s', port = %d, tls = %d, enc_type = %d, basedn = '%s', user_attr = '%s', mail_attr = '%s', login_php = '%s', filter_php = '%s' WHERE sid = %d", $values['name'], $values['server'], $values['port'], $values['tls'], $values['enc_type'], $values['basedn'], trim($values['user_attr']), trim($values['mail_attr']), trim($values['login_php']), trim($values['filter_php']), $values['sid']);
          if ($values['bindpw_clear']) {
            db_query("UPDATE {ldap_servers} SET bindpw = '' WHERE sid = %d", $values['sid']);
          }
        }
        else {
          db_query("UPDATE {ldap_servers} SET name = '%s', server = '%s', port = %d, tls = %d, enc_type = %d, basedn = '%s', user_attr = '%s', mail_attr = '%s', binddn = '%s', bindpw = '%s', login_php = '%s', filter_php = '%s' WHERE sid = %d", $values['name'], $values['server'], $values['port'], $values['tls'], $values['enc_type'], $values['basedn'], trim($values['user_attr']), trim($values['mail_attr']), $values['binddn'], $values['bindpw'], trim($values['login_php']), trim($values['filter_php']), $values['sid']);
        }
        drupal_set_message(t('LDAP server %name has been updated.', array('%name' => $values['name'])));
        watchdog('ldap_api', 'LDAP server %name has been updated.', array('%name' => $values['name']));
      }

      $form_state['redirect'] = 'admin/settings/ldap/servers/list';
      break;
    case t('Test'):
    //      global $_ldap_api_ldap;
      if (isset($values['sid']) && _ldap_api_init($values['sid'])) {
        // Try to authenticate.
        $dn = $_ldap_api_ldap->getOption('binddn');
        $pass = $_ldap_api_ldap->getOption('bindpw');
        if (!$_ldap_api_ldap->connect($dn, $pass)) {
          drupal_set_message(t('Authentication with the LDAP server for the dn %dn and saved password failed.', array('%dn' => $dn)), 'error');
        }
        else {
          drupal_set_message(t('Authentication with the LDAP server for the dn %dn and saved password succeeded.', array('%dn' => $dn)));
        }
      }
      else {
        drupal_set_message(t('Cannot load server settings. Please save configuration first.'), 'error');
      }
      break;
  }
}

/**
 * De-activates the LDAP server.
 *
 * @param $form_State
 *   A form_state array.
 * @param $sid
 *   A LDAP server ID.
 *
 * @return
 *  Form array.
 */
function ldap_api_deactivate_server($sid) {
  if (is_numeric($sid) && ($name = db_result(db_query("SELECT name from
  {ldap_servers} WHERE sid = %d", $sid)))) {
    $form['sid'] = array('#type' => 'hidden', '#value' => $sid);

    return confirm_form($form, t('Are you sure you want to de-activate the server %name?', array('%name' => $name)), 'admin/settings/ldap/servers/list', '', t('De-activate'), t('Cancel'));
  }
  else {
    drupal_not_found();
    exit;
  }
}

/**
 * De-activates the LDAP server.
 *
 * @return
 */
function ldap_api_deactivate_server_submit($form, &$form_state) {
  $sid = $form_state['values']['sid'];
  $result = db_query("SELECT name from {ldap_server} WHERE sid = %d", $sid);
  if ($row = db_fetch_object($result)) {
    db_query("UPDATE {ldap_server} SET active = '0' WHERE sid = %d", $sid);
    drupal_set_message(t('LDAP server %name has been de-activated.', array('%name' => $row->name)));
    watchdog('ldap_api', 'LDAP server %name was de-activated.', array('%name' => $row->name));
  }
  drupal_goto('admin/settings/ldap/servers/list');
}

/**
 * Activates the LDAP server.
 *
 * @param $form_State
 *   A form_state array.
 * @param $sid
 *   A LDAP server ID.
 *
 * @return
 *  Form array.
 */
function ldap_api_activate_server($sid) {
  if (is_numeric($sid) && ($name = db_result(db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid)))) {
    $form['sid'] = array('#type' => 'hidden', '#value' => $sid);

    return confirm_form($form, t('Are you sure you want to activate the server %name?', array('%name' => $name)), 'admin/settings/ldap/server/list', '', t('Activate'), t('Cancel'));
  }
  else {
    drupal_not_found();
    exit;
  }
}

/**
 * Activates the LDAP server.
 *
 * @return
 */
function ldap_api_activate_server_submit($form, &$form_state) {
  $sid = $form_state['values']['sid'];
  $result = db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid);
  if ($row = db_fetch_object($result)) {
    db_query("UPDATE {ldap_servers} SET active = '1' WHERE sid = %d", $sid);
    drupal_set_message(t('LDAP server %name has been activated.', array('%name' => $row->name)));
    watchdog('ldap_api', 'LDAP server %name was activated.', array('%name' => $row->name));
  }
  drupal_goto('admin/settings/ldap/servers/list');
}

/**
 * Implements the LDAP server delete page.
 *
 * @param $form_state
 *   A form state array.
 * @param $sid
 *   A LDAP server ID.
 *
 * @return
 *   The form structure.
 */
function ldap_api_delete_server($sid) {
  if (is_numeric($sid) && ($name = db_result(db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid)))) {
    $form = array(
      'sid' => array('#type' => 'hidden', '#value' => $sid),
      'name' => array('#type' => 'hidden', '#value' => $name),
    );

    return confirm_form($form, t('Are you sure you want to delete the LDAP server named %name?', array('%name' => $name)), 'admin/settings/ldap/servers/list', NULL, t('Delete'), t('Cancel'));
  }
  else {
    drupal_not_found();
    exit;
  }
}

/**
 * Submit hook for the LDAP server delete page.
 */
function ldap_api_delete_server_submit($form, &$form_state) {
  $values = $form_state['values'];
  if ($values['confirm'] && $values['sid']) {
    db_query("DELETE FROM {ldap_servers} WHERE sid = %d", $values['sid']);
    drupal_set_message(t('LDAP server %name has been deleted.', array('%name' => $values['name'])));
    watchdog('ldap_servers', 'LDAP server %name has been deleted.', array('%name' => $values['name']));
  }
  drupal_goto('admin/settings/ldap/servers/list');
}

/**
 * Returns an array of valid encryption types.
 *
 *  *Most of the code here is from phpLDAPadmin.
 */
function valid_enc_types() {

  // Clear Text
  $valid_types[0] = t('Clear');

  // Crypt + Salted Crypt
  $valid_types[1] = t('Crypt');
  $valid_types[2] = t('Salted Crypt');

  // Extended DES
  if ( defined( 'CRYPT_EXT_DES' ) || CRYPT_EXT_DES == 1 )
    $valid_types[3] = t('Extended DES');

  // MD5Crypt
  if ( defined( 'CRYPT_MD5' ) || CRYPT_MD5 == 1 )
    $valid_types[4] = t('MD5Crypt');

  // Blowfish
  if ( defined( 'CRYPT_BLOWFISH' ) || CRYPT_BLOWFISH == 1 )
     $valid_types[5] = t('Blowfish');

  // MD5
  $valid_types[6] = t('MD5');

  // SMD5 + SHA +  SSHA
  if (function_exists( 'mhash' ) && function_exists( 'mhash_keygen_s2k' ) ) {
    $valid_types[7] = t('Salted MD5');
    $valid_types[8] = t('SHA');
    $valid_types[9] = t('Salted SHA');
  }

  return $valid_types;
}

/**
 * Implements the AJAX server test.
 *
 * @param $sid
 *   LDAP server ID.
 *
 * @return
 *   The JSON data.
 */
//function _ldap_api_ajax_test($sid) {
//  global $_ldap_api_ldap;
//
//  if (!is_numeric($sid)) {
//    return;
//  }
//
//  _ldap_api_init($sid);
//
//  if ($_POST['bindpw_clear'] == 'undefined') {
//    $binddn = $_POST['binddn'];
//    $bindpw = $_POST['bindpw'];
//  }
//  else {
//    $binddn = $_ldap_api_ldap->getOption('binddn');
//    $bindpw = $_ldap_api_ldap->getOption('bindpw');
//  }
//
//  drupal_json($_ldap_api_ldap->connect($binddn, $bindpw) ? array('status' => 1, 'message' => t('Authentication with the LDAP server succeeded.')) : array('status' => 0, 'message' => t('Authentication with the LDAP server failed.')));
//  exit;
//}


function _ldap_api_get_ldap_settings() {
  $php_settings = array();
  $phpinfo = _ldap_api_parsePHPModules();
  
  $php_settings['PHP Version'] = phpversion();
  $php_settings['Drupal Version'] = VERSION;
  $php_settings['LDAP Extension Loaded'] = extension_loaded('ldap') ? 'Yes' : 'No';
  
  // set status array to be converted into html table.
  if ($phpinfo['Apache Environment']) {
    $php_settings['SERVER_SOFTWARE'] = $phpinfo['Apache Environment']['SERVER_SOFTWARE'];
  } elseif ( $_SERVER["SERVER_SOFTWARE"]) {
     $php_settings['SERVER_SOFTWARE'] = $_SERVER["SERVER_SOFTWARE"];
  } 
      
  foreach ($phpinfo['ldap'] as $key => $value) {
    $php_settings[$key] = $value[0];
  }     
        
  $modules = module_rebuild_cache();
  $ldapmodules = array('ldap_api', 'ldap_authn', 'ldap_authz', 'ldap_authentication', 'ldap_authorization',);
  foreach ($ldapmodules as $ldapmodule) {
    $php_settings[$ldapmodule]['status'] = $modules[$ldapmodule]->status;
    $php_settings[$ldapmodule]['schema_version'] = $modules[$ldapmodule]->schema_version;
    $php_settings[$ldapmodule]['version'] = $modules[$ldapmodule]->info['version'];
  }     

  return $php_settings;
}

function _ldap_api_parsePHPModules() {
  ob_start();
  phpinfo();
  $s = ob_get_contents();
  ob_end_clean();

  $s = strip_tags($s, '<h2><th><td>');
  $s = preg_replace('/<th[^>]*>([^<]+)<\/th>/', "<info>\\1</info>", $s);
  $s = preg_replace('/<td[^>]*>([^<]+)<\/td>/', "<info>\\1</info>", $s);
  $vtmp = preg_split('/(<h2>[^<]+<\/h2>)/', $s, -1, PREG_SPLIT_DELIM_CAPTURE);
  $vmodules = array();
  for ($i=1; $i<count($vtmp); $i++) {
    if (preg_match('/<h2>([^<]+)<\/h2>/', $vtmp[$i], $vmat)) {
      $vname = trim($vmat[1]);
      $vtmp2 = explode("\n", $vtmp[$i+1]);
      foreach ($vtmp2 AS $vone) {
        $vpat = '<info>([^<]+)<\/info>';
        $vpat3 = "/$vPat\s*$vpat\s*$vpat/";
        $vpat2 = "/$vPat\s*$vpat/";
        if (preg_match($vpat3, $vone, $vmat)) { // 3cols
          $vmodules[$vname][trim($vmat[1])] = array(trim($vmat[2]), trim($vmat[3]));
        }
        elseif (preg_match($vpat2, $vone, $vmat)) { // 2cols
          $vmodules[$vname][trim($vmat[1])] = trim($vmat[2]);
        }
      }
    }
  }
  return $vmodules;
}



// vim:fenc=utf-8:ft=php:ai:si:ts=2:sw=2:et:
