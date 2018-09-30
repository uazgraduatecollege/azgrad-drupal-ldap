<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_user\Event\LdapUserDeletedEvent;

/**
 * Class UpdateLdapEntry.
 */
class LdapEntryDeletionSubscriber extends LdapEntryBaseSubscriber implements LdapUserAttributesInterface {

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[LdapUserDeletedEvent::EVENT_NAME] = ['deleteProvisionedLdapEntry'];
    return $events;
  }

  /**
   * Delete a provisioned LDAP entry.
   *
   * Given a Drupal account, delete LDAP entry that was provisioned based on it.
   * This is usually none or one entry but the ldap_user_prov_entries field
   * supports multiple and thus we are looping through them.
   *
   * @param \Drupal\ldap_user\Event\LdapUserDeletedEvent $event
   *   Event.
   */
  protected function deleteProvisionedLdapEntry(LdapUserDeletedEvent $event) {
    $triggers = $this->config->get('ldapEntryProvisionTriggers');
    if ($this->provisionsLdapEntriesFromDrupalUsers() && in_array(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE, $triggers)) {
      /** @var \Drupal\user\Entity\User $account */
      $account = $event->account;
      // Determine server that is associated with user.
      $entries = $account->get('ldap_user_prov_entries')->getValue();
      foreach ($entries as $entry) {
        $parts = explode('|', $entry['value']);
        if (count($parts) == 2) {
          list($sid, $dn) = $parts;
          $tokens = [
            '%sid' => $sid,
            '%dn' => $dn,
            '%username' => $account->getAccountName(),
            '%uid' => $account->id(),
          ];
          if ($this->ldapUserManager->setServerById($sid) && $dn) {
            if ($this->ldapUserManager->deleteLdapEntry($dn)) {
              $this->logger->info('LDAP entry on server %sid deleted dn=%dn. username=%username, uid=%uid', $tokens);
            }
          }
          else {
            $this->logger->warning("LDAP server %sid not available, cannot delete record '%dn.'", $tokens);
          }
        }
      }
    }
  }

}
