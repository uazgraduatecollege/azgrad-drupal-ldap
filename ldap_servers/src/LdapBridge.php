<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\CredentialsStorage;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\LdapException;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 *
 */
class LdapBridge {

  /**
   * @var string
   */
  protected $bindMethod;
  protected $bindDn;
  protected $bindPw;

  /**
   * @var \Symfony\Component\Ldap\Ldap
   */
  protected $ldap;

  protected $logger;
  protected $entityManager;

  /**
   * Constructor.
   */
  public function __construct(LoggerChannelInterface $logger, EntityTypeManager $entity_type_manager) {
    $this->logger = $logger;
    $this->entityManager = $entity_type_manager->getStorage('ldap_server');
  }

  /**
   * @param string $sid
   */
  public function setServerById($sid) {
    $server = $this->entityManager->load($sid);
    /** @var \Drupal\ldap_servers\Entity\Server $server */
    if ($server) {
      $this->setServer($server);
    }
  }

  /**
   * @param \Drupal\ldap_servers\Entity\Server $server
   */
  public function setServer(Server $server) {
    $options = new OptionsResolver();
    // TODO: Fix network timeout option
    // $options->setAllowedValues('network_timeout', $this->server->get('timeout'));.
    $parameters = [
      'host' => $server->get('address'),
      'port' => $server->get('port'),
      'encryption' => 'none',
      // TODO network timeout.
      'options' => [],
    ];
    if ($server->get('tls')) {
      $parameters['encryption'] = 'tls';
    }
    $this->bindMethod = $server->get('bind_method');
    $this->bindDn = $server->get('binddn');
    $this->bindPw = $server->get('bindpw');
    $this->ldap = Ldap::create('ext_ldap', $parameters);
  }

  /**
   * Bind (authenticate) against an active LDAP database.
   *
   * @return bool
   */
  public function bind() {

    if ($this->bindMethod == 'anon' ||
      ($this->bindMethod == 'anon_user' && !CredentialsStorage::validateCredentials())) {
      $userDn = NULL;
      $password = NULL;
    }
    else {
      // Default credentials form service account.
      $userDn = $this->bindDn;
      $password = $this->bindPw;

      // Runtime credentials for user binding and password checking.
      if (CredentialsStorage::validateCredentials()) {
        $userDn = CredentialsStorage::getUserDn();
        $password = CredentialsStorage::getPassword();
      }

      if (mb_strlen($password) == 0 || mb_strlen($userDn) == 0) {
        $this->logger->notice("LDAP bind failure due to missing credentials for user userdn=%userdn", [
          '%userdn' => $userDn,
        ]);
        return FALSE;
      }
    }

    try {
      $this->ldap->bind($userDn, $password);
    }
    catch (ConnectionException $e) {
      $this->logger->notice("LDAP connection failure: %message.", [
        '%message' => $e->getMessage(),
      ]);
      return FALSE;
    }
    catch (LdapException $e) {
      $this->logger->notice("LDAP bind failure: %message.", [
        '%message' => $e->getMessage(),
      ]);
      return FALSE;
    }
    return TRUE;
  }

  /**
   * @return \Symfony\Component\Ldap\Ldap
   */
  public function get() {
    return $this->ldap;
  }

}
