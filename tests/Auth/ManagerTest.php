<?php

namespace Logikos\Tests\Auth;

use Logikos\Auth\BadTokenException;
use Logikos\Auth\Exception                as AuthException;
use Logikos\Auth\InvalidEntityException;
use Logikos\Auth\Manager                  as AuthManager;
use Logikos\Auth\Password\Exception       as PasswordException;
use Logikos\Auth\Session                  as AuthSession;
use Logikos\Tests\Mock\Users;
use Phalcon\Di\FactoryDefault as Di;

class ManagerTest extends \PHPUnit_Framework_TestCase {
  
  public static $basedir;
  public $modelname = 'Logikos\\Tests\\Mock\\Users';
  public $di;
  /**
   * @var AuthManager
   */
  public $auth;
  

  public static function setUpBeforeClass() {
    static::$basedir = realpath(substr(__DIR__.'/',0,strrpos(__DIR__.'/','/tests/')+7));
    require_once static::$basedir.'/_bootstrap.php';
    
    @session_start();
  }
  
  public function setup() {
    $this->di = $di = new Di;
    $this->di->set('auth',function() {
      $auth = new AuthManager($this->modelname);
      return $auth;
    },true);
    $this->auth = $this->di->get('auth');
    $this->auth->setUserOption(AuthManager::ATTR_ENTITY, $this->modelname);
    \Logikos\Tests\Mock\Users::resetDb();
  }
  
  public function testInvalidUserModelName() {
    $this->setExpectedException(InvalidEntityException::class);
    $this->auth->setUserOption(AuthManager::ATTR_ENTITY, null);
    $this->auth->getEntity();
  }
  
  public function testCanAddUser() {
    $this->auth->setUserOption(AuthManager::ATTR_EMAIL_REQUIRED,false);
    $this->auth->newUser('tempcke','P@ssW0rd');
    $user = $this->auth->getUserByLogin('tempcke');
    $this->assertEquals('tempcke',$user->getUsername());
  }
  
  public function testEmailRequiredToAddNewUser() {
    $this->auth->setUserOption(AuthManager::ATTR_EMAIL_REQUIRED,true); // this is default anyway...
    $this->setExpectedException(AuthException::class);
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  
  public function testNewUserPassToShort() {
    $this->setExpectedException(PasswordException::class);
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_LEN,10); // default is 8...
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewLowerCaseChars() {
    $this->setExpectedException(PasswordException::class);
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_LOWER,5); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewUpperCaseChars() {
    $this->setExpectedException(PasswordException::class);
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_UPPER,3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewNumbers() {
    $this->setExpectedException(PasswordException::class);
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_NUMBER,3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewSymbols() {
    $this->setExpectedException(PasswordException::class);
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_SYMBOL,3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }

  public function testCantCreateUsernameThatAlreadyExists() {
    $this->setExpectedException(AuthException::class);
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@other.com');
  }
  public function testCantCreateUserWithSameEmailAsOtherUser() {
    $this->setExpectedException(AuthException::class);
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->auth->newUser('johndoe','P@ssW0rd','tempcke@foobar.com');
  }
  

  public function testLoginWithoutTokenFails() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->setExpectedException(BadTokenException::class);
    $this->auth->login('tempcke','P@ssW0rd');
  }
  public function testLoginWithWrongPasswordFails() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->setExpectedException(PasswordException::class);
    $this->auth->login('tempcke','incorrectpassword');
  }
  public function testCanLogin() {
    $this->login();
  }
  public function testLoginExpiration() {
    $this->login();
    $this->auth->setUserOption(AuthManager::ATTR_SESSION_TIMEOUT,-1);
    $this->assertLoginStatusIs(AuthSession::STATUS_EXPIRED,'Session should be expired');
    $this->assertFalse($this->auth->isLoggedIn(),'User should not be logged in due to expired login');
  }
  public function testSessionInvalidForDifferentAddress() {
    $this->login();
    $_SERVER['REMOTE_ADDR'] = 'somethinglese';
    $this->assertLoginStatusIs(AuthSession::STATUS_HIJACKED,'Failed to detect hijacked session');
    $this->assertFalse($this->auth->isLoggedIn(),'User should not be logged in due to REMOTE_ADDR mismatch');
  }
  public function testSessionInvalidForDifferentAgent() {
    $this->login();
    $_SERVER['HTTP_USER_AGENT'] = 'somethinglese';
    $this->assertLoginStatusIs(AuthSession::STATUS_HIJACKED,'Failed to detect hijacked session');
    $this->assertFalse($this->auth->isLoggedIn(),'User should not be logged in due to HTTP_USER_AGENT mismatch');
  }
  
  // read how work factor affects things here: https://docs.phalconphp.com/en/latest/reference/security.html
  public function testCanAdjustEncriptionWorkfactor() {
    
    $this->auth->setUserOption(AuthManager::ATTR_WORKFACTOR,4);
    $start = microtime(true);
    $this->auth->newUser('user1','P@ssW0rd','user1@foobar.com');
    $token = $this->auth->getTokenElement(true);
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('user1','P@ssW0rd');
    $time1 = microtime(true) - $start;
    
    $this->auth->setUserOption(AuthManager::ATTR_WORKFACTOR,6);
    $start = microtime(true);
    $this->auth->newUser('user2','P@ssW0rd','user2@foobar.com');
    $token = $this->auth->getTokenElement(true);
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('user2','P@ssW0rd');
    $time2 = microtime(true) - $start;
    
    $this->assertGreaterThan($time1 * 2, $time2, 'A work factor of 6 should be more than 2x as slow as a workfactor of 4');
  }
  
  
  public function testLoginWithNonExistingUser() {
    $this->setExpectedException(AuthException::class);
    $this->auth->login('foobar','fakepassword');
  }
  
  public function testUserCanRetryLoginWithoutNewToken() {
    // purpose of this test is for ajax submited login forms .. user will still have old token
    // by default phalcon destorys the token in the session if the check passes
    // we need to insure user can try a different password
    
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $token = $this->auth->getTokenElement();
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    
    try {
      $this->auth->login('tempcke','WrongPassword');
    }
    catch(\Logikos\Auth\Password\Exception $e) {
      $this->auth->login('tempcke','P@ssW0rd');
    }
    $this->assertTrue($this->auth->isLoggedIn(),'User should be logged in after entering the wrong password then the right password');
  }
  public function testCanLogout() {
    $this->login();
    $this->auth->logout();
    $this->assertSame(AuthSession::STATUS_NOT_SET, $this->auth->getLoginStatus(), 'Failed to remove session data');
  }
  public function testCanMarkSessionInactive() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $token = $this->auth->getTokenElement();
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('tempcke','P@ssW0rd');
    $this->auth->markSessionInactive();
    $this->assertLoginStatusIs(AuthSession::STATUS_INACTIVE,'Session should be inactive');
    $this->auth->reActivate('P@ssW0rd');
    $this->assertLoginStatusIs(AuthSession::STATUS_VALID,'Session should be valid now');
  }
  public function testCanReactivateSession() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $token = $this->auth->getTokenElement();
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('tempcke','P@ssW0rd');
    $this->auth->markSessionInactive();
    $this->assertLoginStatusIs(AuthSession::STATUS_INACTIVE,'Session should be inactive');
    $this->auth->reActivate('P@ssW0rd');
    $this->assertLoginStatusIs(AuthSession::STATUS_VALID,'Session should be valid now');
  }
  public function testCantReactivateSessionWithWrongPassword() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $token = $this->auth->getTokenElement();
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('tempcke','P@ssW0rd');
    $this->auth->markSessionInactive();
    $this->assertLoginStatusIs(AuthSession::STATUS_INACTIVE,'Session should be inactive');
    $this->setExpectedException(PasswordException::class);
    $this->auth->reActivate('wrongP@$$');
    $this->assertLoginStatusIs(AuthSession::STATUS_INACTIVE,'Session should still be inactive');
  }
  
  
  public function assertLoginStatusIs($status, $message=null) {
    $this->assertTrue($this->auth->isLoginStatus($status), $message);
  }
  protected function login() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $token = $this->auth->getTokenElement();
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('tempcke','P@ssW0rd');
  }
}