<?php
namespace Logikos\Tests\Validation\Validator;

use Logikos\Auth\Manager as AuthManager;
use Logikos\Validation\Validator\PasswordStrength;
use Phalcon\Validation;
use Phalcon\Validation\Message;
use Phalcon\Validation\Validator;

class PasswordStrengthTest extends \PHPUnit_Framework_TestCase {
  public static $basedir;
  
  public static function setUpBeforeClass() {
    static::$basedir = realpath(substr(__DIR__.'/',0,strrpos(__DIR__.'/','/tests/')+7));
    require_once static::$basedir.'/_bootstrap.php';
  }
  
  public function testMinLengthPass() {
    $this->assertValidationPass(
        [AuthManager::ATTR_PASS_MIN_LEN => 3],
        'abc'
    );
  }
  public function testMinLengthFail() {
    $this->assertValidationFail(
        [AuthManager::ATTR_PASS_MIN_LEN => 4],
        'abc'
    );
  }
  public function testMinLowerPass() {
    $this->assertValidationPass(
        [AuthManager::ATTR_PASS_MIN_LOWER => 3],
        'abc'
    );
  }
  public function testMinLowerFail() {
    $this->assertValidationFail(
        [AuthManager::ATTR_PASS_MIN_LOWER => 4],
        'abc'
    );
  }
  public function testMinUpperPass() {
    $this->assertValidationPass(
        [AuthManager::ATTR_PASS_MIN_UPPER => 3],
        'ABC'
    );
  }
  public function testMinUpperFail() {
    $this->assertValidationFail(
        [AuthManager::ATTR_PASS_MIN_UPPER => 4],
        'ABC'
    );
  }
  public function testMinNumberPass() {
    $this->assertValidationPass(
        [AuthManager::ATTR_PASS_MIN_NUMBER => 3],
        '123'
    );
  }
  public function testMinNumberFail() {
    $this->assertValidationFail(
        [AuthManager::ATTR_PASS_MIN_NUMBER => 4],
        '123'
    );
  }
  public function testMinSymbolPass() {
    $this->assertValidationPass(
        [AuthManager::ATTR_PASS_MIN_SYMBOL => 3],
        '!@#'
    );
  }
  public function testMinSymbolFail() {
    $this->assertValidationFail(
        [AuthManager::ATTR_PASS_MIN_SYMBOL => 4],
        '!@#'
    );
  }
  protected function assertValidationPass($requirments, $passwd) {
    $count = $this->countValidationMessages($requirments, $passwd);
    $this->assertSame(0, $count, 'Should not be any validation messages');
  }
  protected function assertValidationFail($requirments, $passwd) {
    $count = $this->countValidationMessages($requirments, $passwd);
    $this->assertGreaterThan(0, $count, 'Should be at least one validation message');
  }
  protected function countValidationMessages($requirments, $passwd) {
    return count($this->getValidationMessages($requirments, $passwd));
  }
  protected function getValidationMessages($requirments, $passwd) {
    $ps = new PasswordStrength($requirments);
    $v  = new Validation([['password', $ps]]);
    return $v->validate(['password' => $passwd]);
  }
}