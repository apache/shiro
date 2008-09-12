/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jsecurity.authz.aop;

import org.apache.commons.beanutils.PropertyUtils;
import org.jsecurity.aop.MethodInvocation;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.authz.annotation.RequiresPermissions;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.PermissionUtils;

import java.util.Set;

/**
 * Checks to see if a @{@link RequiresPermissions RequiresPermissions} annotation is declared, and if so, performs
 * a permission check to see if the calling <code>Subject</code> is allowed to call the method.
 * @author Les Hazlewood
 * @since 0.9
 */
public class PermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /**
     * The character to look for that closes a permission definition.
     */
    private static final char ARRAY_CLOSE_CHAR = ']';

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * @{@link RequiresPermissions RequiresPermissions} annotations in a method declaration.
     */
    public PermissionAnnotationMethodInterceptor() {
        super(RequiresPermissions.class);
    }

    /**
     * Infers the permission from the specified name path in the annotation.
     * @param methodArgs the <code>MethodInvocation</code> method arguments.
     * @param namePath the Annotation 'name' value, which is a string-based permission definition.
     * @return the String permission representation.
     * @throws Exception if there is an error infering the target.
     */
    protected String inferTargetFromPath(Object[] methodArgs, String namePath) throws Exception {
        int propertyStartIndex = -1;

        char[] chars = namePath.toCharArray();
        StringBuilder buf = new StringBuilder();
        //init iteration at index 1 (instead of 0).  This is because the first
        //character must be the ARRAY_OPEN_CHAR (eliminates unnecessary iteration)
        for (int i = 1; i < chars.length; i++) {
            if (chars[i] == ARRAY_CLOSE_CHAR) {
                // skip the delimiting period after the ARRAY_CLOSE_CHAR.  The resulting
                // index is the init of the property path that we'll use with
                // BeanUtils.getProperty:
                propertyStartIndex = i + 2;
                break;
            } else {
                buf.append(chars[i]);
            }
        }

        Integer methodArgIndex = Integer.parseInt(buf.toString());
        String beanUtilsPath = new String(chars, propertyStartIndex,
                chars.length - propertyStartIndex);
        Object targetValue = PropertyUtils.getProperty(methodArgs[methodArgIndex], beanUtilsPath);
        return targetValue.toString();
    }

    /**
     * Returns the <code>MethodInvocation</code>'s arguments, or <code>null</code> if there were none.
     * @param invocation the methodInvocation to inspect.
     * @return the method invocation's method arguments, or <code>null</code> if there were none.
     */
    protected Object[] getMethodArguments(MethodInvocation invocation) {
        if (invocation != null) {
            return invocation.getArguments();
        } else {
            return null;
        }
    }

    /**
     * Returns the annotation {@link RequiresPermissions#value value}, from which the Permission will be constructed.
     *
     * @param invocation the method being invoked.
     * @return the method annotation's <code>value</code>, from which the Permission will be constructed.
     */
    protected String getAnnotationValue(MethodInvocation invocation) {
        RequiresPermissions prAnnotation = (RequiresPermissions) getAnnotation(invocation);
        return prAnnotation.value();
    }

    /**
     * Ensures that the calling <code>Subject</code> has the Annotation's specified permissions, and if not, throws an
     * <code>AuthorizingException</code> indicating the method is not allowed to be executed.
     *
     * @param mi the method invocation to check for one or more permissions
     * @throws AuthorizationException if the calling <code>Subject</code> does not have the permission(s) necessary to
     * invoke the method.
     */
    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        String p = getAnnotationValue(mi);
        Set<String> perms = PermissionUtils.toPermissionStrings(p);

        Subject subject = getSubject();

        if (perms.size() == 1) {
            if (!subject.isPermitted(perms.iterator().next())) {
                String msg = "Calling Subject does not have required permission [" + p + "].  " +
                        "Method invocation denied.";
                throw new UnauthorizedException(msg);
            }
        } else {
            String[] permStrings = new String[perms.size()];
            permStrings = perms.toArray(permStrings);
            if (!subject.isPermittedAll(permStrings)) {
                String msg = "Calling Subject does not have required permissions [" + p + "].  " +
                        "Method invocation denied.";
                throw new UnauthorizedException(msg);
            }

        }
    }


}
