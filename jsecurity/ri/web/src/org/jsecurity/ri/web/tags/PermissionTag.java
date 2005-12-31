package org.jsecurity.ri.web.tags;

import org.jsecurity.authz.InstancePermission;
import org.jsecurity.ri.util.PermissionUtils;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;
import java.security.Permission;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public abstract class PermissionTag extends SecureTag {

    private String type = null;
    private String target = null;
    private String actions = null;

    public PermissionTag() {
    }

    public String getType() {
        return type;
    }

    public void setType( String type ) {
        this.type = type;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget( String target ) {
        this.target = target;
    }

    public String getActions() {
        return actions;
    }

    public void setActions( String actions ) {
        this.actions = actions;
    }

    protected void verifyAttributes() throws JspException {
        String type = getType();
        String target = getTarget();
        String actions = getActions();

        if ( type == null ) {
            String msg = "the 'type' tag attribute must be set";
            throw new JspException( msg );
        }

        if ( target == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "'target' tag attribute was not specified.  Assuming default of " +
                           "\"*\", as all Permission objects must be instantiated with a " +
                           "name/target." );
            }
            setTarget( InstancePermission.WILDCARD );
        }
    }

    public int onDoStartTag() throws JspException {

        Permission p = null;

        String actions = getActions();

        if ( actions == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "No actions attribute specified, creating permission with target only." );
            }
            p = PermissionUtils.createPermission( getType(), getTarget() );
        } else {
            p = PermissionUtils.createPermission( getType(), getTarget(), actions );
        }

        boolean show = showTagBody( p );
        if ( show ) {
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            return TagSupport.SKIP_BODY;
        }
    }

    protected abstract boolean showTagBody( Permission p );

}
