<?php

namespace Drupal\ldap_query\Plugin\views\sort;

use Drupal\ldap_query\Plugin\views\VariableAttributeCustomization;
use Drupal\views\Plugin\views\sort\Standard;

/**
 * @ingroup views_sort_handlers
 *
 * @ViewsSort("ldap_variable_attribute")
 */
class LdapVariableAttribute extends Standard {
  use VariableAttributeCustomization;

}
