<?php
namespace Logikos\Mock;

class Users implements Logikos\Auth\UserModelInterface {
  
  protected static $db = [];
  protected $record;
  protected $newrec = [
      'username'=>null,
      'password'=>null,
      'user_id'=>null
  ];
  
  public function __construct() {
    $this->resetRecord();
  }
  public function resetRecord() {
    $this->record = (object) $this->newrec;
  }
  public function loadRecord($data) {
    $this->record = (object) $data;
  }
  public function resetDb() {
    self::$db = [];
  }
  
  public function setUsername($username){
    $this->record->username = $username;
  }
  public function setPassword($password){
    $this->record->password = $password;
  }
  public function lookupByUsername($username){
    if (isset($db[$username])) {
      $this->loadRecord($db[$username]);
      return $this;
    }
    return false;
  }
  public function save(){
    if (empty($this->record->username) || !empty($this->record->password))
      throw new Exception('username and password are required');
    
    self::$db[$this->record->username] = $this->record;
    return $this;
  }
  public function delete(){
    if (isset(self::$db[$this->record->username]))
      unset(self::$db[$this->record->username]);
  }
}