package org.apache.shiro.cas;

import org.apache.shiro.authc.RememberMeAuthenticationToken;

/**
 * This class represents a token for a CAS authentication (service ticket + user id + remember me).
 *
 * @since 1.2
 */
public class CasToken implements RememberMeAuthenticationToken {
    
    private static final long serialVersionUID = 8587329689973009598L;
    
    // the service ticket returned by the CAS server
    private String ticket = null;
    
    // the user identifier
    private String userId = null;
    
    // is the user in a remember me mode ?
    private boolean isRememberMe = false;
    
    public CasToken(String ticket) {
        this.ticket = ticket;
    }
    
    public Object getPrincipal() {
        return userId;
    }
    
    public Object getCredentials() {
        return ticket;
    }
    
    public void setUserId(String userId) {
        this.userId = userId;
    }
    
    public boolean isRememberMe() {
        return isRememberMe;
    }
    
    public void setRememberMe(boolean isRememberMe) {
        this.isRememberMe = isRememberMe;
    }
}
