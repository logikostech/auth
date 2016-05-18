<?php

namespace Logikos\Tests\Auth;

use Logikos\Auth\Manager as AuthManager;

class ManagerTest extends \PHPUnit_Framework_TestCase {
  static $di;
  

  public static function setUpBeforeClass() {
    require_once substr(__DIR__.'/',0,strrpos(__DIR__.'/','/tests/')+7).'bootstrap.php';

    static::$di = \Phalcon\Di::getDefault();
  }
  
  public function testFoo() {
    $this->assertTrue(true);
  }
}