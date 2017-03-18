<?php

namespace Drupal\ldap_views\Plugin\views\query;

use Drupal\views\Plugin\views\query\QueryPluginBase;

/**
 * Views query plugin for an SQL query.
 *
 * @ingroup views_query_plugins
 *
 * @ViewsQuery(
 *   id = "views_ldap_query",
 *   title = @Translation("LDAP Query"),
 *   help = @Translation("Query will be generated and run via LDAP.")
 * )
 */
class LdapQuery extends QueryPluginBase {



}
