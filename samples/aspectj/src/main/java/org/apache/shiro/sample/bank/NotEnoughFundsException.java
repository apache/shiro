package org.apache.shiro.sample.bank;


public class NotEnoughFundsException extends BankServiceException {

  public NotEnoughFundsException(String aMessage) {
    super(aMessage);
  }
  
}
