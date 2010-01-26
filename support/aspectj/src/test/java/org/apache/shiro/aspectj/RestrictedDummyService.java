package org.apache.shiro.aspectj;

import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 * Extends the secure dummy service and makes it some access more restrictive.
 * 
 * @author J-C Desrochers
 */
public class RestrictedDummyService extends SecuredDummyService {

  @RequiresPermissions("dummy:admin")
  public void retrieve() {
    log("retrieve *RESTRICTED*");
    super.retrieve();
  }

  
}
