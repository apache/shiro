/*
 * Copyright (C) 2005 Les Hazlewood, Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.web.tags;

import org.jsecurity.authz.InstancePermission;
import org.jsecurity.util.PermissionUtils;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;
import java.security.Permission;

/**
 * @since 0.1
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
            if ( log.isTraceEnabled() ) {
                log.trace( "'target' tag attribute was not specified.  Assuming default of " +
                           "\"*\", as all Permission objects must be instantiated with a " +
                           "name/target." );
            }
            setTarget( InstancePermission.WILDCARD );
        }

        if ( (actions != null ) && actions.trim().equals( "" ) ) {
            String msg = "Empty actions attribute - please remove the attribute or enter " +
                         "one or more meaningful actions.";
            throw new JspException( msg );
        }
    }

    public int onDoStartTag() throws JspException {

        Permission p = null;

        String actions = getActions();

        if ( actions == null ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "No actions attribute specified, creating permission with target only." );
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
