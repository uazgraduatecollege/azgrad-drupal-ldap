<?php

/**
 * @file
 * Contains \Drupal\ldap_feeds\Feeds\Fetcher\Form\LdapUserFetcherForm.
 */

namespace Drupal\ldap_feeds\Feeds\Fetcher\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\feeds\Plugin\Type\ExternalPluginFormBase;
use Drupal\Core\Url;

/**
 * The configuration form for http fetchers.
 */
class LdapUserFetcherForm extends ExternalPluginFormBase {

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form['filterldapauthenticated'] = [
      '#type' => 'checkbox',
      '#title' => t("Only return LDAP authenticated users."),
      '#description' => t("Only return LDAP authenticated users. If checked, only users who are associated with LDAP accounts will be returned.")
    ];
     
    return $form;
  }

}
