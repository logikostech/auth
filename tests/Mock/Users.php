<?php
namespace Logikos\Tests\Mock;

use Logikos\Auth\UserModelInterface;
use Exception;

/**
 * Obvious this is a mock model, so dont just copy the code to use as a real model
 * as user records will expire with the shell process.
 * it is assumed that real models will store user info in a database somehow
 * you may want email's stored in the same table with the users or different table
 * its up to you!
 * @author tempcke
 */
class Users implements UserModelInterface {
  
  protected static $db = [
  ];
  protected $record;
  protected $newrec = [
      'username' => null,
      'password' => null,
      'email'    => [],
      'user_id'  => null
  ];
  
  public function __construct($record=null) {
    $this->resetRecord($record);
  }

  
  public function setUsername($username) {
    $this->record->username = $username;
  }
  public function setPassword($password) {
    $this->record->password = $password;
  }
  public function addEmail($email) {
    $this->record->email[] = $email;
  }
  public function getUserId() {
    return $this->getUsername();
  }
  public function getUsername() {
    return $this->record->username;
  }
  public function getPassword() {
    return $this->record->password;
  }
  public function getPrimaryEmail() {
    return isset($this->record->email[0])
      ? $this->record->email[0]
      : null;
  }
  public function getUserByLogin($login) {
    $login  = strtolower($login);
    $record = null;
    foreach(self::$db as $user) {
      if (isset($user->email)) {
        foreach($user->email as $email) {
          if (strtolower($email) === $login) {
            $record = $user; break;
          }
        }
      }
      if (strtolower($user->username) === $login) {
        $record = $user; break;
      }
    }
    return $record
      ? $this->newInstance($record)
      : false;
  }
  
  public function getUserByUsername($username) {
    return isset(self::$db[$username])
      ? $this->newInstance(self::$db[$username])
      : false;
  }
  public function getUserByEmail($lookupemail) {
    $record = false;
    if (!empty($lookupemail)) {
      $lookupemail  = strtolower($lookupemail);
      foreach(self::$db as $user) {
        if (isset($user->email)) {
          foreach($user->email as $email) {
            if (strtolower($email) === $lookupemail) {
              $record = $user; break;
            }
          }
        }
      }
    }
    return $record
      ? $this->newInstance($record)
      : false;
  }
  public function getUserById($userid) {
    return $this->getUserByUsername($userid);
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
  

  public function newInstance($record=null) {
    return new Users($record);
  }
  public function resetRecord($record=null) {
    if (is_null($record)) {
      $record = $this->newrec;
    }
    $this->loadRecord($record);
  }
  public function loadRecord($data) {
    $this->record = (object) $data;
    return $this;
  }
  public static function resetDb() {
    self::$db = [];
  }
}