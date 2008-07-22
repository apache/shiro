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
package org.jsecurity.samples.sprhib.eis;

import java.io.Serializable;
import java.util.Collection;

/**
 * Behavioral specification for any object specializing in accessing, updating, and storing data in
 * an EIS.  The methods are common to all forms of EIS's, not just relational databases, meaning
 * this interface should be implemented by <i>all</i> DataAccessObject implementations, regardless
 * of the EIS technology.
 *
 * @author Les Hazlewood
 */
public interface DataAccessObject {

    /**
     * Returns the generated ID for the given entity.
     *
     * @param entity the entity to create in the EIS.
     * @return the generated id after entity creation in the EIS.
     */
    Serializable create(Object entity);

    void update(Object entity);

    void delete(Object entity);

    void deleteById(Class entityType, Serializable id);

    void deleteAll(Collection entities);
}
