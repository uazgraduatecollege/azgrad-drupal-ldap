<?php

declare(strict_types = 1);

namespace Drupal\ldap_user\Plugin;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\DefaultPluginManager;

/**
 * The LDAP authorization provider for authorization module.
 *
 * @AuthorizationProvider(
 *   id = "authorization_provider_dummy",
 *   label = @Translation("Dummy")
 * )
 */
class MappingPlugin extends DefaultPluginManager {

  /**
   * {@inheritdoc}
   */
  public function buildRowForm(array $form, FormStateInterface $form_state, $index = 0) {
    $row = [];
    /** @var \Drupal\authorization\Entity\AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $mappings = $profile->getProviderMappings();
    $row['foo'] = [
      '#type' => 'textfield',
      '#title' => $this->t('LDAP foo'),
      '#default_value' => $mappings[$index]['foo'] ?? NULL,
    ];

    return $row;
  }

}
