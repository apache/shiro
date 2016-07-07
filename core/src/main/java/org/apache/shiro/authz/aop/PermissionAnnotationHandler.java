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
package org.apache.shiro.authz.aop;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.PermissionParam;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.subject.Subject;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * Checks to see if a @{@link org.apache.shiro.authz.annotation.RequiresPermissions RequiresPermissions} annotation is
 * declared, and if so, performs a permission check to see if the calling <code>Subject</code> is allowed continued
 * access.
 *
 * @since 0.9.0
 */
public class PermissionAnnotationHandler extends AuthorizingAnnotationHandler {

    /**
     * Default no-argument constructor that ensures this handler looks for
     * {@link org.apache.shiro.authz.annotation.RequiresPermissions RequiresPermissions} annotations.
     */
    public PermissionAnnotationHandler() {
        super(RequiresPermissions.class);
    }

    /**
     * Returns the annotation {@link RequiresPermissions#value value}, from which the Permission will be constructed.
     *
     * @param a the RequiresPermissions annotation being inspected.
     * @return the annotation's <code>value</code>, from which the Permission will be constructed.
     */
    protected String[] getAnnotationValue(Annotation a) {
        RequiresPermissions rpAnnotation = (RequiresPermissions) a;
        return rpAnnotation.value();
    }

    /**
     * Ensures that the calling <code>Subject</code> has the Annotation's specified permissions, and if not, throws an
     * <code>AuthorizingException</code> indicating access is denied.
     *
     * @param a the RequiresPermission annotation being inspected to check for one or more permissions
     * @throws org.apache.shiro.authz.AuthorizationException
     *          if the calling <code>Subject</code> does not have the permission(s) necessary to
     *          continue access or execution.
     */
    public void assertAuthorized(Annotation a) throws AuthorizationException {
        this.assertAuthorized(a, null);
    }

    public void assertAuthorized(final Annotation a, final MethodInvocation arguments) {
        if (!(a instanceof RequiresPermissions)) return;

        RequiresPermissions rpAnnotation = (RequiresPermissions) a;
        String[] perms = processTemplatedPermissions(getAnnotationValue(a), arguments);
        Subject subject = getSubject();

        if (perms.length == 1) {
            subject.checkPermission(perms[0]);
            return;
        }
        if (Logical.AND.equals(rpAnnotation.logical())) {
            getSubject().checkPermissions(perms);
            return;
        }
        if (Logical.OR.equals(rpAnnotation.logical())) {
            // Avoid processing exceptions unnecessarily - "delay" throwing the exception by calling hasRole first
            boolean hasAtLeastOnePermission = false;
            for (String permission : perms) {
                if (getSubject().isPermitted(permission)) {
                    hasAtLeastOnePermission = true;
                }
            }
            // Cause the exception if none of the role match, note that the exception message will be a bit misleading
            if (!hasAtLeastOnePermission) {
                getSubject().checkPermission(perms[0]);
            }

        }
    }

    /**
     * Manages @see org.apache.shiro.authz.annotation.PermissionParam
     *
     * @param perms raw permissions array
     * @param mi current method invocation
     * @return the permission array with templates replaced from parameters
     */
    private String[] processTemplatedPermissions(final String[] perms, final MethodInvocation mi) {
        if ( mi == null || mi.getArguments() == null || mi.getArguments().length == 0) {
            return perms;
        }

        final Map<String, Object> values = new HashMap<String, Object>();
        for (int p = 0; p < perms.length; p++) {
            if (perms[p].contains("{")) { // return fast if no template
                if (values.isEmpty()) { // init values lazily
                    final Method mtd = mi.getMethod();
                    final Annotation[][] parameterAnnotations = mtd.getParameterAnnotations();
                    for (int a = 0; a < parameterAnnotations.length; a++) {
                        for (int b = 0; b < parameterAnnotations[a].length; b++) {
                            if (PermissionParam.class.equals(parameterAnnotations[a][b].annotationType())) {
                                values.put(PermissionParam.class.cast(parameterAnnotations[a][b]).value(), mi.getArguments()[a]);
                            }
                        }
                    }
                }
                perms[p] = replace(perms[p], values);
            }
        }

        return perms;
    }

    private String replace(final String perm, final Map<String, Object> values) {
        final char[] array = perm.toCharArray();
        final StringBuilder result = new StringBuilder();

        StringBuilder currentParam = null;
        for (final char anArray : array) {
            if (anArray == '{') {
                if (currentParam != null) {
                    throw new IllegalArgumentException("Nested parameters are not supported");
                } else {
                    currentParam = new StringBuilder();
                }
            } else if (anArray == '}') {
                if (currentParam == null) {
                    throw new IllegalArgumentException("missing '{'");
                }

                final String name = currentParam.toString();
                result.append(extractValue(name, values));
                currentParam = null;
            } else if (currentParam != null) {
                currentParam.append(anArray);
            } else {
                result.append(anArray);
            }
        }

        return result.toString();
    }

    private String extractValue(final String name, final Map<String, Object> values) {
        final Object o;
        final int dotIndex = name.indexOf('.');
        if (dotIndex > 0) {
            final String param = name.substring(0, dotIndex);
            final Object instance = values.get(param);
            if (instance == null) {
                o = "";
            } else {
                try {
                    o = PropertyUtils.getProperty(instance, name.substring(dotIndex + 1));
                } catch (final Exception e) {
                    throw new IllegalArgumentException("attribute '" + name + "' not found in " + instance);
                }
            }
        } else {
            o = values.get(name);
        }

        if (o == null) {
            return "";
        }
        return o.toString();
    }
}
