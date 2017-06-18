<?php

namespace Drupal\ldap_query\Plugin\views\argument;

use Drupal\views\Plugin\views\argument\Standard;

/**
 * @ingroup views_argument_handlers
 *
 * @ViewsArgument("ldap_attribute")
 */
class LdapAttribute extends Standard {

  public function query($group_by = FALSE) {
    parent::query($group_by);
    $this->query->addWhere(0, $this->realField, $this->argument, '=');
  }
}