package org.apache.shiro.sample.bank;


public class InactiveAccountException extends BankServiceException {

  public InactiveAccountException(String aMessage) {
    super(aMessage);
  }
  
}
