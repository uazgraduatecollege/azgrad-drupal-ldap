<?php

/**
 * @file
 * theming functions for ldap_servers module
 *
 */

function theme_ldap_servers_https_required($vars) {

  if (!isset($vars['site_contact_link']) || empty($vars['site_contact_link'])) {
    $vars['site_contact_link'] = 'site admin';
  }
  return t("You are accessing site_name using an unencrypted connection. For your security,
     site_name only supports account logins using a secure protocol such as HTTPS. You can switch
     to HTTPS by trying to view this page again after changing the URL in your browser's
     location bar to begin with \"https\" instead of \"http\". Please contact
      site_contact_link for help if this error continues.", $vars);

}
