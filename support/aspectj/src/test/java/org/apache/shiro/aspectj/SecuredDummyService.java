package org.apache.shiro.aspectj;

import java.sql.Timestamp;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;

/**
 * Secured implementation of te dummy service that requires some permissions to execute.
 * 
 * @author J-C Desrochers
 */
public class SecuredDummyService implements DummyService {

  @RequiresAuthentication
  @RequiresPermissions("dummy:admin")
  public void change() {
    retrieve();
    log("change");
    peek();
  }

  public void anonymous() {
    log("anonymous");
  }

  @RequiresAuthentication
  public void guest() {
    log("guest");
  }
  
  @RequiresUser
  public void peek() {
    log("peek");
  }

  @RequiresPermissions("dummy:user")
  public void retrieve() {
    log("retrieve");
  }
  
  public void log(String aMessage) {
    if (aMessage != null) {
      System.out.println(new Timestamp(System.currentTimeMillis()).toString() + " [" + Thread.currentThread() + "] * LOG * " + aMessage);
    } else {
      System.out.println("\n\n");
    }
  }

}
