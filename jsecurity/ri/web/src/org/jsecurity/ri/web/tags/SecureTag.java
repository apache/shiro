package org.jsecurity.ri.web.tags;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.ri.util.PermissionUtils;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;

import javax.servlet.jsp.tagext.TagSupport;
import javax.servlet.jsp.JspException;
import java.security.Permission;

/**
 * @author Les Hazlewood
 */
public abstract class SecureTag extends TagSupport {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public SecureTag(){}

    protected AuthorizationContext getAuthorizationContext() {
        return SecurityContext.getAuthorizationContext();
    }

    protected void verifyAttributes() throws JspException {
    }

    public int doStartTag() throws JspException {

        verifyAttributes();

        return onDoStartTag();
    }

    public abstract int onDoStartTag() throws JspException;
}
