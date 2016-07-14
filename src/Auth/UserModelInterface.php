<?php
namespace Logikos\Auth;

interface UserModelInterface {
  public function setUsername($username);
  public function setPassword($password);
  public function addEmail($email);
  
  // if you dont use userid's just return the username
  // the purpose is to get a unique key for the record
  public function getUserId();
  public function getUsername();
  public function getPassword();
  public function getPrimaryEmail();
  
  /**
   * @param string $username
   * @return UserModelInterface
   */
  public function getUserByLogin($login);
  
  public function getUserByUsername($username);
  public function getUserByEmail($email);
  public function getUserById($userid);
  
  /**
   * @return UserModelInterface
   */
  public function save();
  public function delete();
}