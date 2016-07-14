<?php
namespace Logikos\Validation\Validator;

use Logikos\Auth\Manager as AuthManager;
use Phalcon\Validation;
use Phalcon\Validation\Message;
use Phalcon\Validation\Validator;

class PasswordStrength extends Validator {
  
  protected $fail = [];
  protected $field;
  protected $password;
  
  /**
   * @var Validation
   */
  protected $validation;
  
  public function validate(Validation $validation, $field) {
    $this->validation = $validation;
    $this->field      = $field;
    $this->password   = $this->getValue();
    return $this->isSecure();
  }

  public function isSecure() {
    $min = $this->getMinLimits();
    if (strlen($this->password) < $min->length) {
      $this->appendMessage("Password to short, must be at least {$min->length} chars long");
    }
    if ($this->countLower($this->password) < $min->lower) {
      $this->appendMessage("Password must contain at least {$min->lower} lower case chars");
    }
    if ($this->countUpper($this->password) < $min->upper) {
      $this->appendMessage("Password must contain at least {$min->upper} upper case chars");
    }
    if ($this->countDigits($this->password) < $min->numbers) {
      $this->appendMessage("Password must contain at least {$min->numbers} numbers");
    }
    if ($this->countSymbols($this->password) < $min->symbols) {
      $this->appendMessage("Password must contain at least {$min->symbols} symbols");
    }
    return count($this->getMessages() === 0);
  }
  
  /**
   * @param string $text
   * @param string $message 
   * @param string $type 
   * @param int $code
   * @return \Phalcon\Validation\Message
   */
  protected function appendMessage($text, $type=null, $code=null) {
    $message = new Message($text, $this->field, $type, $code);
    $this->validation->appendMessage($message);
    return $message;
  }
  
  /**
   * @return array
   */
  public function getMessages() {
    $this->validation->getMessages()->filter($this->field);
  }
  
  protected function getValue() {
    return $this->validation->getValue($this->field);
  }
  
  public function isValid() {
    return count($this->fail) === 0;
  }

  public function getMinLimits() {
    return (object) [
        'length'  => $this->getOption(AuthManager::ATTR_PASS_MIN_LEN,0),
        'numbers' => $this->getOption(AuthManager::ATTR_PASS_MIN_NUMBER,0),
        'symbols' => $this->getOption(AuthManager::ATTR_PASS_MIN_SYMBOL,0),
        'upper'   => $this->getOption(AuthManager::ATTR_PASS_MIN_UPPER,0),
        'lower'   => $this->getOption(AuthManager::ATTR_PASS_MIN_LOWER,0)
    ];
  }
  public function countDigits($string) {
    return preg_match_all("/[0-9]/", $string);
  }
  public function countLower($string) {
    return preg_match_all("/[a-z]/", $string);
  }
  public function countUpper($string) {
    return preg_match_all("/[A-Z]/", $string);
  }
  public function countSymbols($string) {
    $pattern = '';
    $symbols = str_split($this->getValidSymbols());
    
    foreach($symbols as $char) {
      $pattern .= "\\{$char}";
    }
    
    return preg_match_all("/[{$pattern}]/", $string);
  }
  public function getValidSymbols() {
    return $this->getOption(
        AuthManager::ATTR_PASS_SYMBOLS,
        AuthManager::defaultUserOptions()[AuthManager::ATTR_PASS_SYMBOLS]
    );
  }
}