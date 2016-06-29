<?php

namespace Logikos\Tests\Auth;

use Logikos\Auth\Manager as AuthManager;
use Logikos\Auth\Logikos\Auth;
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
    $this->setExpectedException('Logikos\Auth\InvalidEntityException');
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
    $this->setExpectedException('Logikos\Auth\Exception');
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  public function testLoginWithoutTokenFails() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->setExpectedException('Logikos\Auth\BadTokenException');
    $this->auth->login('tempcke','P@ssW0rd');
  }
  
  public function testLoginWithWrongPasswordFails() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->setExpectedException('Logikos\Auth\Password\Exception');
    $this->auth->login('tempcke','incorrectpassword');
  }

  public function testCanLogin() {
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $token = $this->auth->getTokenElement();
    $expected = '<input type="hidden"';
    $this->assertStringStartsWith($expected, $token);
    
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login('tempcke','P@ssW0rd');
  }

  public function testNewUserPassToShort() {
    $this->setExpectedException('Logikos\Auth\Password\ToShortException');
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_LEN,10); // default is 8...
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewLowerCaseChars() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewLowerException');
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_LOWER,5); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewUpperCaseChars() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewUpperException');
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_UPPER,3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewNumbers() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewNumbersException');
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_NUMBER,3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }
  public function testNewUserPassWithToFewSymbols() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewSymbolsException');
    $this->auth->setUserOption(AuthManager::ATTR_PASS_MIN_SYMBOL,3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
  }

  public function testCantCreateUsernameThatAlreadyExists() {
    $this->setExpectedException('Logikos\Auth\Exception');
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@other.com');
  }
  public function testCantCreateUserWithSameEmailAsOtherUser() {
    $this->setExpectedException('Logikos\Auth\Exception');
    $this->auth->newUser('tempcke','P@ssW0rd','tempcke@foobar.com');
    $this->auth->newUser('johndoe','P@ssW0rd','tempcke@foobar.com');
  }
  
}