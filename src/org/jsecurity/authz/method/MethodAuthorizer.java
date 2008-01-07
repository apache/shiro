/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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
package org.jsecurity.authz.method;

/**
 * A MethodAuthorizer is asked to vote on whether or not a user/subject is
 * authorized to execute a given Method.
 * Based on the votes from a set of {@link MethodAuthorizer}s, the
 * {@link org.jsecurity.authz.Authorizer Authorizer} will decide
 * whether or not to authorize the user to perform the action.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface MethodAuthorizer {

    /**
     * Determines whether or not this MethodAuthorizer supports voting on
     * the given MethodInvocation.  Returning false indicates that this module will not
     * be called to vote on authorizing the MethodInvocation.
     *
     * @param invocation the method invocation which this module must decide if it supports.
     * @return true if this module supports the given invocation, false otherwise.
     */
    boolean supports( MethodInvocation invocation );

    /**
     * Called when this MethodAuthorizer needs to vote on whether or not
     * the current {@link org.jsecurity.context.SecurityContext} is authorized to
     * execute the specified MethodInvocation.  This method is only called if this
     * MethodAuthorizer {@link #supports supports} the specified invocation.
     *
     * @param invocation the MethodInvocation about to be executed.
     * @return a vote indicating whether or not this MethodAuthorizer grants or denies
     * authorization to the caller, or abstains from voting.
     */
    AuthorizationVote isAuthorized( MethodInvocation invocation );

}

