/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.interceptor;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.ClassUtils;
import org.jsecurity.web.interceptor.authc.BasicHttpAuthenticationWebInterceptor;
import org.jsecurity.web.interceptor.authc.FormAuthenticationWebInterceptor;
import org.jsecurity.web.interceptor.authz.PermissionsAuthorizationWebInterceptor;
import org.jsecurity.web.interceptor.authz.RolesAuthorizationWebInterceptor;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultInterceptorBuilder implements InterceptorBuilder {

    protected transient final Log log = LogFactory.getLog(getClass());

    public Map<String, Object> buildDefaultInterceptors() {
        Map<String, Object> interceptors = new LinkedHashMap<String, Object>();
        interceptors.put("authc", new FormAuthenticationWebInterceptor());
        interceptors.put("authcBasic", new BasicHttpAuthenticationWebInterceptor());
        interceptors.put("roles", new RolesAuthorizationWebInterceptor());
        interceptors.put("perms", new PermissionsAuthorizationWebInterceptor());
        return interceptors;
    }

    public Map<String, Object> buildInterceptors(String config) {

        Map<String, Object> interceptors = buildDefaultInterceptors();

        if (config != null) {
            Scanner scanner = new Scanner(config);
            while (scanner.hasNextLine()) {

                String definitionLine = scanner.nextLine().trim();

                if (!definitionLine.equals("") && !definitionLine.startsWith("#")) {

                    if (log.isTraceEnabled()) {
                        log.trace("Parsing interceptor definition line [" + definitionLine + "]");
                    }

                    String[] parts = definitionLine.split("=", 2);
                    if (parts == null || parts.length != 2) {
                        String msg = "Config parsing error - each configuration line must have the format:  key = value";
                        throw new IllegalStateException(msg);
                    }

                    String key = parts[0].trim();
                    String value = parts[1].trim();

                    buildInterceptor(key, value, interceptors);
                }

            }
            scanner.close();
        }


        return interceptors;
    }

    protected Object newInstance(String propValue) {
        return ClassUtils.newInstance(propValue);
    }

    public void buildInterceptor(String key, String value, Map<String, Object> interceptors) {

        int index = key.indexOf('.');

        if (index >= 0) {
            String name = key.substring(0, index);
            String property = key.substring(index + 1, key.length());
            Object interceptor = interceptors.get(name);
            if (interceptor == null) {
                if (property.equals("class")) {
                    interceptor = newInstance(value);
                    interceptors.put(name, interceptor);
                } else {
                    String msg = "Configuration error.  Specified Interceptor [" + name + "] with property [" +
                            property + "] without first defining that interceptor/filter's class.  Please first " +
                            "specify the class property first, e.g. myInterceptor.class = fully_qualified_class_name " +
                            "and then define additional properties.";
                    throw new IllegalArgumentException(msg);
                }
            } else {
                applyProperty(interceptor, property, value);
            }
        } else {
            //no period, assume the prop is just the name only:
            Object interceptor = interceptors.get(key);
            if (interceptor == null) {
                //name with no property, assume right hand side of equals sign is the class name:
                interceptor = newInstance(value);
                interceptors.put(key, interceptor);
            }
        }
    }

    protected void applyProperty(Object interceptor, String propertyName, String value) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Applying property [" + propertyName + "] value [" + value + "] on interceptor of type [" + interceptor.getClass().getName() + "]");
            }
            BeanUtils.setProperty(interceptor, propertyName, value);
        } catch (Exception e) {
            String msg = "Unable to set property [" + propertyName + "] with value [" + value + "]";
            throw new IllegalArgumentException(msg, e);
        }
    }
}
