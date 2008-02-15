/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;

/**
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public abstract class PermissionTag extends SecureTag {

    private String permission = null;

    public PermissionTag() {
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    protected void verifyAttributes() throws JspException {
        String permission = getPermission();

        if ( permission == null || permission.length() == 0 ) {
            String msg = "The 'permission' tag attribute must be set.";
            throw new JspException( msg );
        }
    }

    public int onDoStartTag() throws JspException {

        String p = getPermission();

        boolean show = showTagBody( p );
        if ( show ) {
            return TagSupport.EVAL_BODY_INCLUDE;
        } else {
            return TagSupport.SKIP_BODY;
        }
    }

    protected boolean isPermitted( String p ) {
        return getSecurityContext() != null && getSecurityContext().isPermitted( p );
    }

    protected abstract boolean showTagBody( String p );

}
