package org.jsecurity.web.filter.authz;

import org.jsecurity.JSecurityException;
import org.jsecurity.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Map;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class RolesAuthorizationWebInterceptor extends AuthorizationWebInterceptor {

    public void init() throws JSecurityException {
        //convert applied URLs values to a Set of Roles:
        if (this.appliedUrls != null && !this.appliedUrls.isEmpty()) {
            this.appliedUrls = tokenizeValues((Map<String,String>)this.appliedUrls);
        }
    }

    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        Subject subject = getSubject(request, response);
        Set<String> roles = (Set<String>)mappedValue;

        if ( roles != null && !roles.isEmpty() ) {
            if ( roles.size() == 1 ) {
                if ( !subject.hasRole(roles.iterator().next())) {
                    issueRedirect(request,response);
                }
            } else {
                if ( !subject.hasAllRoles(roles) ) {
                    issueRedirect(request,response);
                }
            }
        }

        return true;
    }
}
