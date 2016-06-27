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
    $this->auth->setUserOption('entity', $this->modelname);
    \Logikos\Tests\Mock\Users::resetDb();
  }
  
  public function testInvalidUserModelName() {
    $this->setExpectedException('Logikos\Auth\InvalidEntityException');
    $this->auth->setUserOption('entity', null);
    $this->auth->getEntity();
  }
  
  public function testCanAddUser() {
    $post = $this->mockUserData();
    $this->auth->newUser($post['username'],$post['password']);
    
    $user = $this->auth->getUserByLogin($post['username']);
    $this->assertEquals($post['username'],$user->getUsername());
  }

  public function testLoginWithoutTokenFails() {
    $this->addTestUser();
    $post = $this->mockUserData();
    $this->setExpectedException('Logikos\Auth\BadTokenException');
    $this->auth->login($post['username'],$post['password']);
  }
  
  public function testLoginWithWrongPasswordFails() {
    $this->addTestUser();
    $post = $this->mockUserData();
    $this->setExpectedException('Logikos\Auth\Password\Exception');
    $this->auth->login($post['username'],'incorrectpassword');
  }

  public function testCanLogin() {
    $this->addTestUser();
    $post  = $this->mockUserData();
    $token = $this->auth->getTokenElement();
    $expected = '<input type="hidden"';
    $this->assertStringStartsWith($expected, $token);
    
    $_POST[$this->auth->tokenkey] = $this->auth->tokenval;
    $this->auth->login($post['username'], $post['password']);
  }

  public function testNewUserPassMinReqOk() {
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  public function testNewUserPassToShort() {
    $this->setExpectedException('Logikos\Auth\Password\ToShortException');
    $this->auth->setUserOption('minpass_length',10); // default is 8...
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  public function testNewUserPassWithToFewLowerCaseChars() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewLowerException');
    $this->auth->setUserOption('minpass_lowercase',5); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  public function testNewUserPassWithToFewUpperCaseChars() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewUpperException');
    $this->auth->setUserOption('minpass_uppercase',3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  public function testNewUserPassWithToFewNumbers() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewNumbersException');
    $this->auth->setUserOption('minpass_numbers',3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  public function testNewUserPassWithToFewSymbols() {
    $this->setExpectedException('Logikos\Auth\Password\ToFewSymbolsException');
    $this->auth->setUserOption('minpass_symbols',3); // default is 1
    $this->auth->newUser('tempcke','P@ssW0rd');
  }
  
  
  
  protected function getUserModel() {
    return new Users();
  }
  protected function addTestUser() {
    $post = $this->mockUserData();
    $this->auth->newUser($post['username'],$post['password']);
  }
  protected function mockUserData() {
    return [
        'username' => 'tempcke',
        'password' => 'MyGr3@+P@$s'
    ];
  }
}