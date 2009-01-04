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
package org.jsecurity.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;

/**
 * //TODO - complete JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractResource implements Serializable {

    public AbstractResource() {
    }

    public AbstractResource(String resourcePath) {
        load(resourcePath);
    }

    public AbstractResource(InputStream is) {
        load(is);
    }

    public void load(String resourcePath) {
        if (resourcePath == null) {
            throw new IllegalArgumentException("resourcePath argument cannot be null.");
        }
        InputStream is = getPathInputStream(resourcePath);
        load(is);
    }

    protected InputStream getPathInputStream(String path) throws ResourceException {
        try {
            return ResourceUtils.getInputStreamForPath(path);
        } catch (IOException e) {
            String msg = "Unable to create input stream from resource path [" + path + "].";
            throw new ResourceException(msg, e);
        }
    }

    public void load(InputStream is) throws ResourceException {
        try {
            doLoad(is);
        } catch (Exception e) {
            String msg = "Unable to load data from input stream [" + is + "].";
            throw new ResourceException(msg, e);
        }
    }

    protected abstract void doLoad(InputStream is) throws Exception;
}
