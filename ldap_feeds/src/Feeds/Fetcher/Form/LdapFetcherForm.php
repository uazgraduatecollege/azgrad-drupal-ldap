<?php

/**
 * @file
 * Contains \Drupal\ldap_feeds\Feeds\Fetcher\Form\LdapFetcherForm.
 */

namespace Drupal\ldap_feeds\Feeds\Fetcher\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\feeds\Plugin\Type\ExternalPluginFormBase;

/**
 * The configuration form for http fetchers.
 */
class LdapFetcherForm extends ExternalPluginFormBase {

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    return $form;
  }

}
