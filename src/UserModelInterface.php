<?php
namespace Logikos\Auth;

interface UserModelInterface {
  public function setUsername($username);
  public function setPassword($password);
  public function addEmail($email);
  
  public function getUsername();
  public function getPassword();
  public function getPrimaryEmail();
  
  /**
   * @param string $username
   * @return UserModelInterface
   */
  public function getUserByLogin($login);
  
  public function lookupUserByUsername($username);
  public function lookupUserByEmail($email);
  
  /**
   * @return UserModelInterface
   */
  public function save();
  public function delete();
}