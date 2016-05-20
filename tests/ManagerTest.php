<?php

namespace Logikos\Tests\Auth;

use Logikos\Auth\Manager as AuthManager;
use Logikos\Auth\Manager;

class ManagerTest extends \PHPUnit_Framework_TestCase {
  static $di;
  

  public static function setUpBeforeClass() {
    require_once substr(__DIR__.'/',0,strrpos(__DIR__.'/','/tests/')+7).'bootstrap.php';

    static::$di = \Phalcon\Di::getDefault();
  }
  
  public function testInvalidUserModelName() {
    $this->setExpectedException('Exception');
    $userModelName = null;
    new Manager($userModelName);
  }
}