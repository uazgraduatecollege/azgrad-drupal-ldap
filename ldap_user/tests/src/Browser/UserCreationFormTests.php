<?php

namespace Drupal\Tests\ldap_user\Browser;

use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\Tests\BrowserTestBase;

/**
 * @group ldap
 */
class UserCreationFormTests extends BrowserTestBase {

  protected function setUp() {
    parent::setUp();

  }

 public function testManualUserCreation() {
   $this->assertTrue(true);
   return;
   // TODO

   /**
    * manually create drupal user with option of not ldap associated checked
    */

   if ($hpotter = user_load_by_name('hpotter')) {
     $hpotter->uid->delete();
   }
   $this->assertFalse(user_load_by_name('hpotter'), t('hpotter removed before manual account creation test'), $this->testId('manual non ldap account created'));

   $this->drupalLogout();
   $this->drupalLogin($this->privileged_user);
   $this->drupalGet('admin/people/create');
   $edit = array(
     'name' => 'hpotter',
     'mail' => 'hpotter@hogwarts.edu',
     'pass[pass1]' => 'goodpwd',
     'pass[pass2]' => 'goodpwd',
     'notify' => FALSE,
     'ldap_user_association' => LdapConfiguration::$manualAccountConflictNoLdapAssociate,
   );
   $this->drupalPost('admin/people/create', $edit, t('Create new account'));

   $hpotter = user_load_by_name('hpotter');
   $processor = new DrupalUserProcessor();
   $this->assertTrue($hpotter, t('hpotter created via ui form'), $this->testId('manual non ldap account created'));
   $this->assertTrue($hpotter && !$processor->isUserLdapAssociated($hpotter), t('hpotter not ldap associated'), $this->testId('manual non ldap account created'));

 }
}
