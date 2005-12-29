package org.jsecurity.ri.web.tags;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

    private boolean applyWildcard = true;

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

    /**
     * Returns whether or not to apply the wildcard ('*') if the {@link #getTarget target} or
     * {@link #getActions actions} tag attributes are unspecified.
     *
     * <p>That is, if this property is set to <tt>true</tt> (the default), and the <tt>target</tt> property is not
     * specified (i.e. <tt>null</tt>), the target property will automatically be set to '*'.  And, if the
     * <tt>actions</tt> property is not specified (i.e. <tt>null</tt>), the actions property will automatically be set
     * to '*'.
     *
     * <p>If this attribute is set to <tt>false</tt>, and the <tt>target</tt> or <tt>actions</tt> attributes are not set,
     * this tag considers this state a programming error, and will throw an exception.
     *
     * <p>The default setting is <b><tt>true</tt></b>.
     *
     * @return <tt>true</tt> if the wildcard token should be applied to null <tt>target</tt> or <tt>actions</tt>
     * properties, <tt>false</tt> otherwise.
     *
     */
    public boolean isApplyWildcard() {
        return applyWildcard;
    }

    /**
     * Turns on or off default application of the wildcard token ('*') if the {@link #getTarget target} or
     * {@link #getActions actions} attributes are null.
     *
     * @param applyWildcard whether or not to apply the wildcard token in the event of null attributes.
     * @see #isApplyWildcard
     */
    public void setApplyWildcard( boolean applyWildcard ) {
        this.applyWildcard = applyWildcard;
    }

    protected void verifyAttributes() throws JspException {
        if ( getType() == null ) {
            String msg = "the 'type' tag attribute must be set";
            throw new JspException( msg );
        }
        if ( getTarget() == null ) {
            if ( isApplyWildcard() ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "'target' tag attribute was not specified.  Assuming default of '*'.  If you " +
                        "do not want this default to be applied set the 'applyWildcard' attribute " +
                        "to false." );
                }
                setTarget( "*" );
            } else {
                String msg = "the 'target' tag attribute has not been set and default application of wildcards is " +
                    "turned off.";
                throw new JspException( msg );
            }
        }
        if ( getActions() == null ) {
            if ( isApplyWildcard() ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "'actions' tag attribute was not specified.  Assuming default of '*'.  If you " +
                        "do not want this default to be applied set the 'applyWildcard' attribute " +
                        "to false." );
                }
                setTarget( "*" );
            } else {
                String msg = "the 'actions' tag attribute has not been set and default application of wildcards is " +
                    "turned off.";
                throw new JspException( msg );
            }

        }
    }

    public int onDoStartTag() throws JspException {
        Permission p = PermissionUtils.createPermission( getType(), getTarget(), getActions() );
        boolean show = showTagBody( p );
        if ( show ) {
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            return TagSupport.SKIP_BODY;
        }
    }

    protected abstract boolean showTagBody( Permission p );

}
