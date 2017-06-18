<?php

namespace Drupal\ldap_query\Plugin\views\filter;

use Drupal\views\Plugin\views\filter\StringFilter;

/**
 * @ingroup views_filter_handlers
 *
 * @ViewsFilter("ldap_attribute")
 */
class LdapAttribute extends StringFilter {


  public function operator() {
    return $this->operator == '=' ? '=' : '!=';
  }

  public function opEqual($field) {
    $this->query->addWhere($this->options['group'], $this->realField, $this->value, $this->operator());
  }

  protected function opContains($field) {
    $this->query->addWhere($this->options['group'], $this->realField, "*$this->value*", '=');
  }

  protected function opStartsWith($field) {
    $this->query->addWhere($this->options['group'], $this->realField, "$this->value*", '=');
  }

  protected function opNotStartsWith($field) {
    $this->query->addWhere($this->options['group'], $this->realField, "$this->value*", '!=');
  }

  protected function opEndsWith($field) {
    $this->query->addWhere($this->options['group'], $this->realField, "*$this->value", '=');
  }

  protected function opNotEndsWith($field) {
    $this->query->addWhere($this->options['group'], $this->realField, "*$this->value", '!=');
  }

  protected function opNotLike($field) {
    $this->query->addWhere($this->options['group'], $this->realField, "*$this->value*", '!=');
  }

  protected function opEmpty($field) {
    if ($this->operator == 'empty') {
      $this->query->addWhere($this->options['group'], $this->realField, '*', '!=');
    }
    else {
      $this->query->addWhere($this->options['group'], $this->realField, '*', '=');
    }
  }

   // TODO: Port numerical comparisons. Requires change of base type.

}