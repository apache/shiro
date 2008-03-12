package org.jsecurity.web.filter.authz;

import org.jsecurity.JSecurityException;
import org.jsecurity.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class PermissionsAuthorizationWebInterceptor extends AuthorizationWebInterceptor {

    protected Map<String,String[]> tokenizeValuesToStringArray( Map<String,String> arg ) {
        Map<String,Set<String>> map = tokenizeValues(arg);
        if ( map != null && !map.isEmpty() ) {
            Map<String,String[]> newMap = new LinkedHashMap<String,String[]>(map.size());
            for( Map.Entry<String,Set<String>> entry : map.entrySet() ) {
                Set<String> set = entry.getValue();
                String[] stringArray = new String[set.size()];
                stringArray = (new ArrayList<String>(set)).toArray(stringArray);
                newMap.put( entry.getKey(), stringArray );
            }
            return newMap;
        }
        return null;
    }

    public void init() throws JSecurityException {
        //convert applied URLs values to a Set of Roles:
        if (this.appliedUrls != null && !this.appliedUrls.isEmpty()) {
            this.appliedUrls = tokenizeValuesToStringArray((Map<String,String>)this.appliedUrls);
        }
    }

    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        Subject subject = getSubject(request, response);
        String[] perms = (String[])mappedValue;

        if ( perms != null && perms.length > 0) {
            if ( perms.length == 1 ) {
                if ( !subject.isPermitted(perms[0]) ) {
                    issueRedirect(request,response);
                }
            } else {
                if ( !subject.isPermittedAll(perms) ) {
                    issueRedirect(request,response);
                }
            }
        }

        return true;
    }
}
