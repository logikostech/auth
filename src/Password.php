<?php
namespace Logikos\Auth;

class Password {
  use \Logikos\UserOptionTrait;
  
  protected $password;
  

  public function __construct($password,$options=null) {
    $this->password = $password;
    
    $this->_setDefaultUserOptions(Manager::defaultUserOptions());
    
    if (is_array($options))
      $this->mergeUserOptions($options);
  }

  public function isSecure() {
    $min = $this->getMinLimits();
    if (strlen($this->password) < $min->length) {
      throw new Password\ToShortException("Password to short, must be at least {$min->length} chars long");
    }
  
    if ($this->countLower($this->password) < $min->lower) {
      throw new Password\ToFewLowerException("Password must contain at least {$min->lower} lower case chars");
    }
    if ($this->countUpper($this->password) < $min->upper) {
      throw new Password\ToFewUpperException("Password must contain at least {$min->upper} upper case chars");
    }
    if ($this->countDigits($this->password) < $min->numbers) {
      throw new Password\ToFewNumbersException("Password must contain at least {$min->numbers} numbers");
    }
    if ($this->countSymbols($this->password) < $min->symbols) {
      throw new Password\ToFewSymbolsException("Password must contain at least {$min->symbols} symbols");
    }
  }
  public function getMinLimits() {
    return (object) [
        'length'  => $this->getUserOption(Manager::ATTR_PASS_MIN_LEN),
        'numbers' => $this->getUserOption(Manager::ATTR_PASS_MIN_NUMBER),
        'symbols' => $this->getUserOption(Manager::ATTR_PASS_MIN_SYMBOL),
        'upper'   => $this->getUserOption(Manager::ATTR_PASS_MIN_UPPER),
        'lower'   => $this->getUserOption(Manager::ATTR_PASS_MIN_LOWER)
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
    $symbols = str_split($this->getUserOption(Manager::ATTR_PASS_SYMBOLS));
    
    foreach($symbols as $char) {
      $pattern .= "\\{$char}";
    }
    
    return preg_match_all("/[{$pattern}]/", $string);
  }
}