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
package org.jsecurity.logging.jdk;

import org.jsecurity.logging.Log;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class JdkLog implements Log {

    private final Logger logger;

    public JdkLog(Logger logger) {
        this.logger = logger;
    }

    public String getName() {
        return logger.getName();
    }

    public boolean isTraceEnabled() {
        return logger.isLoggable(Level.FINER);
    }

    public void trace(String msg) {
        logger.log(Level.FINEST, msg);
    }

    public void trace(String format, Object arg) {
        logger.log(Level.FINEST, format, arg);
    }

    public void trace(String format, Object... args) {
        logger.log(Level.FINEST, format, args);
    }

    public void trace(String msg, Throwable t) {
        logger.log(Level.FINEST, msg, t);
    }

    public boolean isDebugEnabled() {
        return logger.isLoggable(Level.CONFIG);
    }

    public void debug(String msg) {
        logger.log(Level.FINE, msg);
    }

    public void debug(String format, Object arg) {
        logger.log(Level.FINE, format, arg);
    }

    public void debug(String format, Object... args) {
        logger.log(Level.FINE, format, args);
    }

    public void debug(String msg, Throwable t) {
        logger.log(Level.FINE, msg, t);
    }

    public boolean isInfoEnabled() {
        return logger.isLoggable(Level.INFO);
    }

    public void info(String msg) {
        logger.log(Level.INFO, msg);
    }

    public void info(String format, Object arg) {
        logger.log(Level.INFO, format, arg);
    }

    public void info(String format, Object... args) {
        logger.log(Level.INFO, format, args);
    }

    public void info(String msg, Throwable t) {
        logger.log(Level.INFO, msg, t);
    }

    public boolean isWarnEnabled() {
        return logger.isLoggable(Level.WARNING);
    }

    public void warn(String msg) {
        logger.log(Level.WARNING, msg);
    }

    public void warn(String format, Object arg) {
        logger.log(Level.WARNING, format, arg);
    }

    public void warn(String format, Object... args) {
        logger.log(Level.WARNING, format, args);
    }

    public void warn(String msg, Throwable t) {
        logger.log(Level.WARNING, msg, t);
    }

    public boolean isErrorEnabled() {
        return logger.isLoggable(Level.SEVERE);
    }

    public void error(String msg) {
        logger.log(Level.SEVERE, msg);
    }

    public void error(String format, Object arg) {
        logger.log(Level.SEVERE, format, arg);
    }

    public void error(String format, Object... args) {
        logger.log(Level.SEVERE, format, args);
    }

    public void error(String msg, Throwable t) {
        logger.log(Level.SEVERE, msg, t);
    }
}
