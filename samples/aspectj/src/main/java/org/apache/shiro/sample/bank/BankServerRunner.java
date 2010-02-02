package org.apache.shiro.sample.bank;


public class BankServerRunner {

  private SecureBankService _bankService;
  
  public synchronized void start() throws Exception {
    if (_bankService == null) {
      _bankService = new SecureBankService();
      _bankService.start();
    }
  }
  
  public synchronized void stop() {
    if (_bankService != null) {
      try {
        _bankService.dispose();
      } finally {
        _bankService = null;
      }
    }
  }
  
  public BankService getBankService() {
    return _bankService;
  }
  
  public static void main(String[] args) {
    try {
      BankServerRunner server = new BankServerRunner();
      server.start();
      
      server.stop();
      
    } catch (Exception e) {
      e.printStackTrace();
    }
    
  }
}
