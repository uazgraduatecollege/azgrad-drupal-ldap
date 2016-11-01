<?php

namespace Drupal\ldap_user;

/**
 *
 */
trait LdapUserConfigurationValues {

  // Provisioning events (events are triggered by triggers).
  public static $eventCreateDrupalUser = 1;
  public static $eventSyncToDrupalUser = 2;
  public static $eventCreateLdapEntry = 3;
  public static $eventSyncToLdapEntry = 4;
  public static $eventLdapAssociateDrupalAccount = 5;

  public static $resultProvisionLdapEntryCreateFailed = 2;
  public static $resultProvisionLdapEntrySyncFailed = 3;

  public static $provisioningDirectionToDrupalUser = 1;
  public static $provisioningDirectionToLDAPEntry = 2;
  public static $provisioningDirectionNone = 3;
  public static $provisioningDirectionAll = 4;

  public static $provisioningResultNoError = 0;
  public static $provisioningResultNoPassword = 1;
  public static $provisioningResultBadParameters = 2;

  // Originally needed to avoid conflicting with server ids.
  public static $noServerSID = 0;

  // Configurable Drupal account provision triggers.
  public static $provisionDrupalUserOnUserUpdateCreate = 1;
  public static $provisionDrupalUserOnAuthentication = 2;
  public static $provisionDrupalUserOnAllowingManualCreation = 3;

  // Configurable ldap entry provision triggers.
  public static $provisionLdapEntryOnUserUpdateCreate = 6;
  public static $provisionLdapEntryOnUserAuthentication = 7;
  public static $provisionLdapEntryOnUserDelete = 8;

  // Options for account creation behavior.
  public static $accountCreationLdapBehaviour = 4;
  public static $accountCreationUserSettingsForLdap = 1;


  public static $userConflictLog = 1;
  public static $userConflictAttemptResolve = 2;

  public static $manualAccountConflictReject = 1;
  public static $manualAccountConflictLdapAssociate = 2;
  public static $manualAccountConflictShowOptionOnForm = 3;
  public static $manualAccountConflictNoLdapAssociate = 4;

}
