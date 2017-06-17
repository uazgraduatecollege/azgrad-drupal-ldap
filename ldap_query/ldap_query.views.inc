<?php

/**
 * Implements hook_views_data().
 */
function ldap_query_views_data() {
  $data['ldap_query']['table']['group'] = t('LDAP Query');

  $data['ldap_query']['table']['base'] = [
    'query_id' => 'ldap_query',
    'title' => t('LDAP Query'),
    'help' => t('Data from LDAP Server.'),
  ];

  // Fields.
  $data['ldap_query']['dn'] = [
    'title' => t('DN'),
    'help' => t('Distinguished name attribute.'),
    'field' => [
      'id' => 'ldap_attribute',
    ],/*
    'sort' => [
      'handler' => 'ldap_views_handler_sort',
    ],
   */
    'filter' => [
      'id' => 'ldap_attribute',
    ],
  ];
  $data['ldap_query']['attribute'] = [
    'title' => t('LDAP Attribute'),
    'help' => t('An attribute in an LDAP server.'),
    /*'argument' => [
      'handler' => 'ldap_views_handler_argument_attribute',
    ],*/
    'field' => [
      'id' => 'ldap_variable_attribute',
    ],/*
    'sort' => [
      'handler' => 'ldap_views_handler_sort_attribute',
    ],*/
    'filter' => [
      'id' => 'ldap_variable_attribute',
    ],
  ];

  $data['ldap_query']['cn'] = [
    'title' => t('CN'),
    'help' => t('Common name attribute.'),
  /*  'argument' => [
      'handler' => 'ldap_views_handler_argument',
    ],*/
    'field' => [
      'id' => 'ldap_attribute',
    ],/*
    'sort' => [
      'handler' => 'ldap_views_handler_sort',
    ],
   */
    'filter' => [
      'id' => 'ldap_attribute',
    ],
  ];
  $data['ldap_query']['objectClass'] = [
    'title' => t('Object Class'),
    'help' => t('The LDAP object class attribute.'),
   /* 'argument' => [
      'handler' => 'ldap_views_handler_argument',
    ],*/
    'field' => [
      'id' => 'ldap_attribute',
    ],/*
    'sort' => [
      'handler' => 'ldap_views_handler_sort',
    ],
    */
    'filter' => [
      'id' => 'ldap_attribute',
    ],
  ];

  return $data;
}