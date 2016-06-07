<?php

/**
 * @file
 * Contains \Drupal\ldap_feeds\Feeds\Fetcher\LdapFetcher.
 */

namespace Drupal\ldap_feeds\Feeds\Fetcher;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\File\FileSystemInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\feeds\Exception\EmptyFeedException;
use Drupal\feeds\FeedInterface;
use Drupal\feeds\Plugin\Type\ClearableInterface;
use Drupal\feeds\Plugin\Type\FeedPluginFormInterface;
use Drupal\feeds\Plugin\Type\Fetcher\FetcherInterface;
use Drupal\feeds\Plugin\Type\PluginBase;
use Drupal\feeds\Result\HttpFetcherResult;
use Drupal\feeds\StateInterface;
use Drupal\feeds\Utility\Feed;

/**
 * Defines an LDAP fetcher.
 *
 * @FeedsFetcher(
 *   id = "ldap",
 *   title = @Translation("LDAP query"),
 *   description = @Translation("Retrieves data from an LDAP server using LDAPS's query module."),
 *   configuration_form = "Drupal\ldap_feeds\Feeds\Fetcher\Form\LDAPFetcherForm",
 *   arguments = {"@cache.feeds_download", "@file_system"}
 * )
 */
class LDAPFetcher extends PluginBase implements ClearableInterface, FeedPluginFormInterface, FetcherInterface {

  /**
   * The cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cache;

  /**
   * Drupal file system helper.
   *
   * @var \Drupal\Core\File\FileSystemInterface
   */
  protected $fileSystem;

  /**
   * Constructs an UploadFetcher object.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin id.
   * @param array $plugin_definition
   *   The plugin definition.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The cache backend.
   * @param \Drupal\Core\File\FileSystemInterface $file_system
   *   The Drupal file system helper.
   */
  public function __construct(array $configuration, $plugin_id, array $plugin_definition, CacheBackendInterface $cache, FileSystemInterface $file_system) {
    $this->client = $client;
    $this->cache = $cache;
    $this->fileSystem = $file_system;
    parent::__construct($configuration, $plugin_id, $plugin_definition);
  }

  /**
   * {@inheritdoc}
   */
  public function fetch(FeedInterface $feed, StateInterface $state) {
    
    // @TODO
    // Perform an LDAP query

    return;
  }

  /**
   * {@inheritdoc}
   */
  public function clear(FeedInterface $feed, StateInterface $state) {
    $this->onFeedDeleteMultiple([$feed]);
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'request_timeout' => 30,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildFeedForm(array $form, FormStateInterface $form_state, FeedInterface $feed) {
    if ( $servers = ldap_servers_get_servers(NULL, 'enabled') ) {
      $options = array();
      foreach ($servers as $server_id => $ldap_server) {
        $enabled = ($ldap_server->get('status')) ? 'Enabled' : 'Disabled';
        $options[$server_id] = $ldap_server->label() . ' (' . $ldap_server->get('address') . ') Status: ' . $enabled;
      }

      $form['server_id'] = [
        '#title' => $this->t('LDAP Server'),
        '#type' => 'radios',
        '#default_value' => $feed->getSource(),
        '#options' => $options,
      ];
    } else {
      // @TODO Create a link here to LDAP Servers.
      $form['markup'] = [
        '#markup' => t("Please enable or create an LDAP server."),
      ];
    }
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateFeedForm(array &$form, FormStateInterface $form_state, FeedInterface $feed) {
  }

  /**
   * {@inheritdoc}
   */
  public function submitFeedForm(array &$form, FormStateInterface $form_state, FeedInterface $feed) {
    $feed->setSource($form_state->getValue('server_id'));
  }

  /**
   * {@inheritdoc}
   */
  public function onFeedDeleteMultiple(array $feeds) {
    foreach ($feeds as $feed) {
      $this->cache->delete($this->getCacheKey($feed));
    }
  }

}
