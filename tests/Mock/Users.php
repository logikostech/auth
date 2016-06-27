<?php
namespace Logikos\Tests\Mock;

use Logikos\Auth\UserModelInterface;
use Exception;

class Users implements UserModelInterface {
  
  protected static $db = [
  ];
  protected $record;
  protected $newrec = [
      'username' => null,
      'password' => null,
      'email'    => null,
      'user_id'  => null
  ];
  
  public function __construct() {
    $this->resetRecord();
  }

  
  public function setUsername($username) {
    $this->record->username = $username;
  }
  public function setPassword($password) {
    $this->record->password = $password;
  }
  public function getUsername() {
    return $this->record->username;
  }
  public function getPassword() {
    return $this->record->password;
  }
  public function getUserByLogin($login) {
    $login  = strtolower($login);
    $record = null;
    foreach(self::$db as $user) {
      if (isset($user->email) && strtolower($user->email) === $login) {
        $record = $user; break;
      }
      elseif (strtolower($user->username) === $login) {
        $record = $user; break;
      }
    }
    return $record
      ? $this->loadRecord($record)
      : false;
      
  }
  public function save(){
    if (empty($this->record->username) || empty($this->record->password))
      throw new Exception('username and password are required');
    
    self::$db[$this->record->username] = $this->record;
    return $this;
  }
  public function delete(){
    if (isset(self::$db[$this->record->username]))
      unset(self::$db[$this->record->username]);
  }
  
  
  public function resetRecord() {
    $this->record = (object) $this->newrec;
  }
  public function loadRecord($data) {
    $this->record = (object) $data;
    return $this;
  }
  public static function resetDb() {
    self::$db = [];
  }
}