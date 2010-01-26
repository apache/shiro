package org.apache.shiro.aspectj;


/**
 * Basic service for test purposes.
 * 
 * @author J-C Desrochers
 */
public interface DummyService {

  public void log(String aMessage);
  
  public void anonymous();

  public void guest();
  
  public void peek();
  
  public void retrieve();
  
  public void change();
}
