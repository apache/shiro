package org.apache.shiro.sample.bank;


public class AccountNotFoundException extends BankServiceException {

  public AccountNotFoundException(String aMessage) {
    super(aMessage);
  }
  
}
