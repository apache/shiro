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
package org.jsecurity.logging;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class NoOpLog implements Log {

    public static transient final NoOpLog INSTANCE = new NoOpLog("NoOp");

    private String name;

    public NoOpLog(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public boolean isTraceEnabled() {
        return false;
    }

    public void trace(String msg) {
    }

    public void trace(String format, Object arg) {
    }

    public void trace(String format, Object... args) {
    }

    public void trace(String msg, Throwable t) {
    }

    public boolean isDebugEnabled() {
        return false;
    }

    public void debug(String msg) {
    }

    public void debug(String format, Object arg) {
    }

    public void debug(String format, Object... args) {
    }

    public void debug(String msg, Throwable t) {
    }

    public boolean isInfoEnabled() {
        return false;
    }

    public void info(String msg) {
    }

    public void info(String format, Object arg) {
    }

    public void info(String format, Object... args) {
    }

    public void info(String msg, Throwable t) {
    }

    public boolean isWarnEnabled() {
        return false;
    }

    public void warn(String msg) {
    }

    public void warn(String format, Object arg) {
    }

    public void warn(String format, Object... args) {
    }

    public void warn(String msg, Throwable t) {
    }

    public boolean isErrorEnabled() {
        return false;
    }

    public void error(String msg) {
    }

    public void error(String format, Object arg) {
    }

    public void error(String format, Object... args) {
    }

    public void error(String msg, Throwable t) {
    }
}
