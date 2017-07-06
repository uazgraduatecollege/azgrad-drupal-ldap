<?php

namespace Drupal\ldap_user\Processor;

use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\user\Entity\User;
use Symfony\Component\HttpFoundation\Response;

/**
 *
 */
class GroupUserUpdateProcessor {

  private $config;

  /**
   * Constructor for update process.
   */
  public function __construct() {
    $this->detailedWatchdog = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
    $this->config = \Drupal::config('ldap_user.settings');
    $this->ldapDrupalUserProcessor = new DrupalUserProcessor();
    $this->ldapServerFactory = new ServerFactory();
    $this->ldapServer = $this->ldapServerFactory
      ->getServerByIdEnabled($this->config->get('drupalAcctProvisionServer'));
  }

  /**
   *
   */
  public function runQuery() {

    // @TODO: Make query dynamic through ldap_user form.
    // @TODO: Move from controller into cron.
    // @TODO: Batch users as orphanprocessor does.
    // @TODO: Fix issue with missing authorizations.

    $queryController = new QueryController('TEMP');
    $queryController->execute();
    $accountsToProcess = $queryController->getRawResults();
    $attribute = $this->ldapServer->get('user_attr');
    \Drupal::logger('ldap_user')->notice('Count: @name', ['@name' => $accountsToProcess['count']]);

    foreach ($accountsToProcess as $account) {
      if (isset($account[$attribute], $account[$attribute][0])) {
        $username = $account[$attribute][0];
        $match = $this->ldapServer->matchUsernameToExistingLdapEntry($username);
        if ($match) {
          if (ExternalAuthenticationHelper::getUidFromIdentifierMap($username)) {
            $drupalAccount = User::load(ExternalAuthenticationHelper::getUidFromIdentifierMap($username));
            $this->ldapDrupalUserProcessor->drupalUserLogsIn($drupalAccount);
            if ($this->detailedWatchdog) {
              \Drupal::logger('ldap_user')
                ->notice('Periodic update: @name updated', ['@name' => $username]);
            }
          }
          else {
            $drupalAccount = $this->ldapDrupalUserProcessor->provisionDrupalAccount(['name' => $username, 'status' => TRUE]);
            $this->ldapDrupalUserProcessor->drupalUserLogsIn($drupalAccount);
            if ($this->detailedWatchdog) {
              \Drupal::logger('ldap_user')->notice('Periodic update: @name created', ['@name' => $username]);
            }
          }
        }
      }
    }
    return new Response();
  }

}
