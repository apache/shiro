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

import org.apache.shiro.aop.AnnotationResolver;

/**
 * Checks to see if a @{@link org.apache.shiro.authz.annotation.RequiresPermissions RequiresPermissions} annotation is declared, and if so, performs
 * a permission check to see if the calling <code>Subject</code> is allowed to call the method.
 * @since 0.9
 */
public class PermissionAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /*
     * The character to look for that closes a permission definition.
     **/
    //private static final char ARRAY_CLOSE_CHAR = ']';

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * {@link org.apache.shiro.authz.annotation.RequiresPermissions RequiresPermissions} annotations in a method declaration.
     */
    public PermissionAnnotationMethodInterceptor() {
        super( new PermissionAnnotationHandler() );
    }

    /**
     * @param resolver
     * @since 1.1
     */
    public PermissionAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super( new PermissionAnnotationHandler(), resolver);
    }

    /*
     * Infers the permission from the specified name path in the annotation.
     * @param methodArgs the <code>MethodInvocation</code> method arguments.
     * @param namePath the Annotation 'name' value, which is a string-based permission definition.
     * @return the String permission representation.
     * @throws Exception if there is an error infering the target.
     *
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

    /*
     * Returns the <code>MethodInvocation</code>'s arguments, or <code>null</code> if there were none.
     * @param invocation the methodInvocation to inspect.
     * @return the method invocation's method arguments, or <code>null</code> if there were none.
     *
    protected Object[] getMethodArguments(MethodInvocation invocation) {
        if (invocation != null) {
            return invocation.getArguments();
        } else {
            return null;
        }
    }

    /*
     * Returns the annotation {@link RequiresPermissions#value value}, from which the Permission will be constructed.
     *
     * @param invocation the method being invoked.
     * @return the method annotation's <code>value</code>, from which the Permission will be constructed.
     *
    protected String getAnnotationValue(MethodInvocation invocation) {
        RequiresPermissions prAnnotation = (RequiresPermissions) getAnnotation(invocation);
        return prAnnotation.value();
    } */
}
