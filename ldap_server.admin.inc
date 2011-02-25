<?php

/**
 * @file
 * Administrative page callbacks for the ldap_api module.
 */

include_once dirname(__FILE__).'/includes/ldap.server.inc';

/**
 * Page callback created in the implementation of hook_menu.
 *
 * @see drupal_get_form()
 */
function ldap_api_list_servers() {
  return drupal_get_form('ldap_api_list_servers_form');
}

/**
 * Server Listing/Weight implimentation of hook_form(). Creating the actual 
 * form itself happens here.
 *
 * @see http://api.drupal.org/api/file/developer/topics/forms_api.html/6
 * @see http://api.drupal.org/api/file/developer/topics/forms_api_reference.html/6
 *
 */
function ldap_api_list_servers_form($form_state) {
  ctools_include('ajax'); // Module  include the dependence it needs for ajax.
  ctools_include('modal');
  ctools_modal_add_js();
  
  $form = array();
  $form['list'] = array();
  $form['list']['#tree'] = TRUE;

  $items = _ldap_api_get_servers();

  foreach ($items as $values) {
    $form['list'][$values->sid]['sid'] = array('#type' => 'hidden', '#value' => $values->sid);
    $form['list'][$values->sid]['name'] = array('#value' => $values->name);
//    $form['list'][$values->sid]['active'] = array('#value' => $values->active);
    $form['list'][$values->sid]['edit'] = array('#value' => l(t('edit'), 'admin/settings/ldap/servers/' . $values->sid . '/edit'));
    $form['list'][$values->sid]['active'] = ($values->active) ? array('#value' => ctools_modal_text_button(t('deactivate'), 'admin/settings/ldap/servers/' . $values->sid . '/deactivate', t('Deactivate this server.'))) : array('#value' => ctools_modal_text_button(t('activate'), 'admin/settings/ldap/servers/' . $values->sid . '/activate', t('Activate this server.')));
    $form['list'][$values->sid]['delete'] = array('#value' => ctools_modal_text_button(t('delete'), 'admin/settings/ldap/servers/' . $values->sid . '/delete', t('Delete this server/')));
    $form['list'][$values->sid]['weight'] = array('#type' => 'weight', '#default_value' => $values->weight);
  }

  $form['submit'] = array('#type'  => 'submit', '#value' => t('Save'));
  $form['add'] = array('#type'  => 'submit', '#value' => t('Add Server'));

  return $form;
}

function _ldap_api_get_servers() {
  $items = array();

  $result = db_query("SELECT * FROM {ldap_servers} ORDER BY weight");
  while ($item = db_fetch_object($result)) {
    $items[] = $item;
  }

  return $items;
}

/**
 * Validate hook for the LDAP server form.
 */
function ldap_api_list_servers_form_validate($form, &$form_state) {
}

/**
 * Submit hook for the LDAP server form.
 */   
function ldap_api_list_servers_form_submit($form, &$form_state) {
  $op = $form_state['clicked_button']['#value'];
  $values = $form_state['values'];
  switch ($op) { 
    case t('Add Server'):
        drupal_goto('admin/settings/ldap/servers/add');
        break;
    case t('Save'):
      foreach ($form_state['values']['list'] as $server) {
        db_query("UPDATE {ldap_servers} SET weight = %d WHERE sid = %d", array($server['weight'], $server['sid']));
      }
      break;
  }

}

/**
 * Page callback created in the implementation of hook_menu.
 *
 * @see drupal_get_form()
 */
function ldap_api_add_server() {
  return drupal_get_form('ldap_api_edit_server_form');
}

/**
 * Page callback created in the implementation of hook_menu.
 *
 * @see drupal_get_form()
 */
function ldap_api_edit_server($sid = NULL) {
  return drupal_get_form('ldap_api_edit_server_form', $sid);
}

/**
 * Server Add/Edit/Modify implimentation of hook_form(). Creating the actual 
 * form itself happens here.
 *
 * @see http://api.drupal.org/api/file/developer/topics/forms_api.html/6
 * @see http://api.drupal.org/api/file/developer/topics/forms_api_reference.html/6
 *
 */
function ldap_api_edit_server_form($form_state, $sid = NULL) {
  drupal_add_js(drupal_get_path('module', 'ldap_api') .'/ldap_server.admin.js');

  $form = array();

  $config = new ldap_server($sid);

  if (!is_null($sid)) {
    $form['sid'] = array (
      '#type' => 'hidden',
      '#value' => $config->sid,
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
    '#default_value' => $config->name,
    '#description' => t('Choose a <em><strong>unique</strong></em> name for this server configuration.'),
    '#size' => 50,
    '#maxlength' => 255,
    '#required' => TRUE,
  );
  $form['server-settings']['address'] = array(
    '#type' => 'textfield',
    '#title' => t('Server Address'),
    '#default_value' => $config->address,
    '#size' => 50,
    '#maxlength' => 255,
    '#description' => t('The domain name or IP address of your LDAP Server.'),
    '#required' => TRUE,
  );
  $form['server-settings']['port'] = array(
    '#type' => 'textfield',
    '#title' => t('LDAP port'),
    '#default_value' => $config->port,
    '#size' => 5,
    '#maxlength' => 5,
    '#description' => t('The TCP/IP port on the above server which accepts LDAP connections. Must be an integer.'),
  );
  $form['server-settings']['tls'] = array(
    '#type' => 'checkbox',
    '#title' => t('Use Start-TLS'),
    '#default_value' => $config->tls,
    '#description' => t('Secure the connection between the Drupal and the LDAP servers using TLS.<br /><em>Note: To use START-TLS, you must set the LDAP Port to 389.</em>'),
  );
  $form['server-settings']['basedn'] = array(
    '#type' => 'textarea',
    '#title' => t('Base DNs'),
    '#default_value' => $config->basedn,
    '#cols' => 50,
    '#rows' => 6,
    '#description' => t('Base DNs for searches. Enter one per line in case you need several of them.'),
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
      '#default_value' => $config->__get('binddn'),
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
      '#value' => $config->__get('binddn'),
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
    '#submit' => array(''),
    '#suffix' => '<div id="test-spinner" style="display: none;">'. theme_image(drupal_get_path('module', 'ldap_api') .'/images/spinner.gif') .'</div><div id="test-message" class="messages" style="display: none;"></div>',
  );

  $form['submit'] = array('#type' => 'submit','#value' => t('Save configuration') );
  $form['cancel'] = array('#type' => 'submit', '#value' => t('Cancel'), '#submit' => array('_submit_cancel') );



  return $form;
}

/**
 * Validate hook for the LDAP server form.
 */
function ldap_api_edit_server_form_validate($form, &$form_state) {
  $values = $form_state['values'];

  // Check for duplicated LDAP Server Names
  if (!isset($values['sid'])) {
    if (db_fetch_object(db_query("SELECT name FROM {ldap_servers} WHERE name = '%s'", $values['name']))) {
      form_set_error('name', t('An LDAP config with the name %name already exists.', array('%name' => $values['name'])));
    }
  }
  elseif (db_fetch_object(db_query("SELECT name FROM {ldap_servers} WHERE name = '%s' and sid != '%d'", $values['name'], $values['sid']))) {
      form_set_error('name', t('An LDAP config with the name %name already exists.', array('%name' => $values['name'])));
  }

  // Ensure that the port number is actually a number.
  if (!is_numeric($values['port'])) {
    form_set_error('port', t('The TCP/IP port must be an integer.'));
  }
}

/**
 * Submit hook for the LDAP server form.
 */   
function ldap_api_edit_server_form_submit($form, &$form_state) {
  $op = $form_state['clicked_button']['#value'];
  $values = $form_state['values'];
  switch ($op) {
    case t('Save configuration'):
      if (!isset($values['sid'])) {
        db_query("INSERT INTO {ldap_servers} (name, active, address, port, tls, basedn, binddn, bindpw) VALUES ('%s', %d, '%s', %d, %d, '%s', '%s', '%s')", $values['name'], 1, $values['address'], $values['port'], $values['tls'], $values['basedn'],  $values['binddn'], $values['bindpw']);
        drupal_set_message(t('LDAP configuration %name has been added.', array('%name' => $values['name'])));
        watchdog('LDAP', 'LDAP configuration %name has been added.', array('%name' => $values['name']));
      }
      else {
        db_query("UPDATE {ldap_servers} SET name = '%s', address = '%s', port = %d, tls = %d, basedn = '%s', binddn = '%s', bindpw = '%s' WHERE sid = %d", $values['name'], $values['address'], $values['port'], $values['tls'], $values['basedn'], $values['binddn'], $values['bindpw'], $values['sid']);
        drupal_set_message(t('LDAP Configuration %name has been updated.', array('%name' => $values['name'])));
        watchdog('ldap_servers', 'LDAP Configuration %name has been updated.', array('%name' => $values['name']));
      }
      $form_state['redirect'] = 'admin/settings/ldap/servers/list';
      break;
    case t('Test'):
//      global $_ldap_servers_ldap;
      if (isset($values['sid']) && _ldap_servers_init($values['sid'])) {
        // Try to authenticate.
        $dn = $_ldap_servers_ldap->getOption('binddn');
        $pass = $_ldap_servers_ldap->getOption('bindpw');
        if (!$_ldap_servers_ldap->connect($dn, $pass)) {
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
 * Page callback created in the implementation of hook_menu.
 *
 * @see ctools_modal_form_wrapper()
 */
function ldap_api_activate_server($sid) {
  if (is_numeric($sid) && (db_query("SELECT sid from {ldap_servers} WHERE sid = %d", $sid))) {
    ctools_include('ajax');
    ctools_include('modal');

    $form_state = array('ajax' => TRUE, 'sid' => $sid);
    $output = ctools_modal_form_wrapper('ldap_api_activate_server_form', $form_state);
    if (!$output) {
      $output = array();
      $output[] = ctools_ajax_command_reload();
      $output[] = ctools_modal_command_dismiss();
    }

    ctools_ajax_render($output);
  }
}

/**
 * activate Server implimentation of hook_form(). Creating the actual 
 * form itself happens here.
 *
 * @see http://api.drupal.org/api/file/developer/topics/forms_api.html/6
 * @see http://api.drupal.org/api/file/developer/topics/forms_api_reference.html/6
 *
 */
function ldap_api_activate_server_form($form_state) {
  $sid = $form_state['sid'];
  $name = db_result(db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid));
  $form['sid'] = array('#type' => 'hidden', '#value' => $sid);
  $form['text'] = array('#value' => t('Are you sure you want to activate the server %name?<br/>', array('%name' => $name)));
  $form['activate'] = array('#type' => 'submit', '#value' => t('Activate') );
  $form['cancel'] = array('#type' => 'submit', '#value' => t('Cancel'), '#submit' => array('_submit_cancel') );

  return $form;
}

/**   
 * Validate hook for the LDAP server form.
 */
function ldap_api_activate_server_form_validate($form, &$form_state) {
} 
    
/** 
 * Submit hook for the LDAP server form.
 */
function ldap_api_activate_server_form_submit($form, &$form_state) {
  if($form_state['values']['op'] == $form_state['values']['Cancel']) {
    return;
  }
  
  $sid = $form_state['values']['sid'];
  $result = db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid);
  if ($row = db_fetch_object($result)) {
    db_query("UPDATE {ldap_servers} SET active = '1' WHERE sid = %d", $sid);
    drupal_set_message(t('LDAP server %name has been activated.', array('%name' => $row->name)));
    watchdog('ldap', 'LDAP server %name was activated.', array('%name' => $row->name));
  }
}

/**
 * Page callback created in the implementation of hook_menu.
 *
 * @see ctools_modal_form_wrapper()
 */
function ldap_api_deactivate_server($sid) {
  if (is_numeric($sid) && (db_query("SELECT sid from {ldap_servers} WHERE sid = %d", $sid))) {
    ctools_include('ajax');
    ctools_include('modal');

    $form_state = array('ajax' => TRUE, 'sid' => $sid);
    $output = ctools_modal_form_wrapper('ldap_api_deactivate_server_form', $form_state);
    if (!$output) {
      $output = array();
      $output[] = ctools_ajax_command_reload();
      $output[] = ctools_modal_command_dismiss();
    }

    ctools_ajax_render($output);
  }
}

/**
 * deactivate Server implimentation of hook_form(). Creating the actual 
 * form itself happens here.
 *
 * @see http://api.drupal.org/api/file/developer/topics/forms_api.html/6
 * @see http://api.drupal.org/api/file/developer/topics/forms_api_reference.html/6
 *
 */
function ldap_api_deactivate_server_form($form_state) {
  $sid = $form_state['sid'];
  $name = db_result(db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid));
  $form['sid'] = array('#type' => 'hidden', '#value' => $sid);
  $form['text'] = array('#value' => t('Are you sure you want to deactivate the server %name?<br/>', array('%name' => $name)));
  $form['deactivate'] = array('#type' => 'submit', '#value' => t('Dectivate') );
  $form['cancel'] = array('#type' => 'submit', '#value' => t('Cancel'), '#submit' => array('_submit_cancel') );

  return $form;
}

/**
 * Validate hook for the LDAP server form.
 */
function ldap_api_deactivate_server_form_validate($form, &$form_state) {
}

/**
 * Submit hook for the LDAP server form.
 */   
function ldap_api_deactivate_server_form_submit($form, &$form_state) {
  $sid = $form_state['values']['sid'];
  $result = db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid);
  if ($row = db_fetch_object($result)) {
    db_query("UPDATE {ldap_servers} SET active = '0' WHERE sid = %d", $sid);
    drupal_set_message(t('LDAP server %name has been deactivated.', array('%name' => $row->name)));
    watchdog('ldap', 'LDAP server %name was deactivated.', array('%name' => $row->name));
  }
}

/**
 * Page callback created in the implementation of hook_menu.
 *
 * @see ctools_modal_form_wrapper()
 */
function ldap_api_delete_server($sid) {
  if (is_numeric($sid) && (db_query("SELECT sid from {ldap_servers} WHERE sid = %d", $sid))) {
    ctools_include('ajax');
    ctools_include('modal');

    $form_state = array('ajax' => TRUE, 'sid' => $sid);
    $output = ctools_modal_form_wrapper('ldap_api_delete_server_form', $form_state);
    if (!$output) {
      $output = array();
      $output[] = ctools_ajax_command_reload();
      $output[] = ctools_modal_command_dismiss();
    }

    ctools_ajax_render($output);
  }
}

/**
 * Delete Server implimentation of hook_form(). Creating the actual 
 * form itself happens here.
 *
 * @see http://api.drupal.org/api/file/developer/topics/forms_api.html/6
 * @see http://api.drupal.org/api/file/developer/topics/forms_api_reference.html/6
 *
 */
function ldap_api_delete_server_form($form_state) {
  $sid = $form_state['sid'];
  $name = db_result(db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid));
  $form['sid'] = array('#type' => 'hidden', '#value' => $sid);
  $form['text'] = array('#value' => t('Are you sure you want to delete the server %name?<br/>', array('%name' => $name)));
  $form['delete'] = array('#type' => 'submit', '#value' => t('Delete') );
  $form['cancel'] = array('#type' => 'submit', '#value' => t('Cancel'), '#submit' => array('_submit_cancel') );

  return $form;
}

/**
 * Validate hook for the LDAP server form.
 */
function ldap_api_delete_server_form_validate($form, &$form_state) {
}

/**
 * Submit hook for the LDAP server form.
 */
function ldap_api_delete_server_form_submit($form, &$form_state) {
  $sid = $form_state['values']['sid'];
  $result = db_query("SELECT name from {ldap_servers} WHERE sid = %d", $sid);
  if ($row = db_fetch_object($result)) {
    db_query("DELETE FROM {ldap_servers} WHERE sid = %d", $sid);
    drupal_set_message(t('LDAP server %name has been deleted.', array('%name' => $row->name)));
    watchdog('ldap', 'LDAP server %name was deleted.', array('%name' => $row->name));
  }
}

function ldap_api_server_name($sid = NULL) {
  $result = db_query("SELECT name FROM {ldap_servers} WHERE sid = %d", $sid);
  $object = db_fetch_object($result);
  
  return $object->name;
}

/**
 * Dummy submit hook. Allows us to cancel the current form action.
 */
function _submit_cancel(){
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
function _ldap_server_ajax_test($sid) {
  if (!is_numeric($sid)) {
    return;
  }

  $server = new ldap_server($sid);

#  if ($_POST['bindpw_clear'] == 'undefined') {
#    $server->set_binddn($_POST['binddn']);
#    $server->set_bindpw($_POST['bindpw']);
#  }

  if (! $server->connect()) {
    drupal_json(array('status' => 0, 'message' => t('Unable to connect to the LDAP server.')));
  }

  drupal_json($server->bind() ? array('status' => 1, 'message' => t('Authentication with the LDAP server succeeded.')) : array('status' => 0, 'message' => t('Authentication with the LDAP server failed.')));

  exit;
}


// vim:fenc=utf-8:ft=php:ai:si:ts=2:sw=2:et:
