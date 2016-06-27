<?php
namespace Logikos\Auth;

interface UserModelInterface {
  public function setUsername($username);
  public function setPassword($password);
  
  public function getUsername();
  public function getPassword();  
  /**
   * @param string $username
   * @return UserModelInterface
   */
  public function getUserByLogin($login);
  
  /**
   * @return UserModelInterface
   */
  public function save();
  public function delete();
}