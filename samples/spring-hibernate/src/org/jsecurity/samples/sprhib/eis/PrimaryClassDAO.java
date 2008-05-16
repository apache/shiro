/*
 * Copyright 2008 Les Hazlewood
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
package org.jsecurity.samples.sprhib.eis;

import org.springframework.dao.DataAccessException;

import java.io.Serializable;
import java.util.List;

/**
 * A convenience behavioral specification for DataAccessObjects that primarily work with one
 * Object/Class type.
 * <p/>
 * Implementations of this interface are by no means restricted to working with their primary type
 * only; indeed they may &quot;know&quot; about any Class needed to accomplish their tasks.  This
 * interface is merely intended to specify convenience behaviors common to all DAO's that
 * <i>mostly</i> work with one data type.
 *
 * @author Les Hazlewood
 */
public interface PrimaryClassDAO extends DataAccessObject {

    /**
     * Returns the primary class for which this DAO is responsible. Most Data Access Objects will
     * work on behalf of a specific object type (e.g. User, Event, etc.).  Implementations of this
     * interface may of course work with any other classes as needed, but a PrimaryClassDAO always
     * has one primary target class it &quot;knows&quot; about for convenience.
     *
     * @return the primary class this DAO works with.
     */
    Class getPrimaryClass();

    /**
     * Reads/retrieves the object of type <code>getPrimaryClass()</code> with the specified id.
     *
     * @param entityId the id identifying the object to retrieve.
     *
     * @return the object with the given entityId
     *
     * @throws org.springframework.dao.DataAccessException
     *          if there is an error accessing the EIS, or if no object of type
     *          <code>getPrimaryClass()</code> with an id of <code>entityId</code> exists in the
     *          EIS.
     */
    Object read( Serializable entityId ) throws DataAccessException;

    /**
     * Retrieves all instances of type <code>getPrimaryClass()</code> found in the EIS.  Use this
     * method judiciously as a very large result set will no doubt incur a performance penalty.
     *
     * @return a List of instances of type <code>getPriamaryClass()</code> found in the EIS.
     *
     * @throws DataAccessException if an error occurs accessing the EIS.
     */
    List readAll() throws DataAccessException;

    /**
     * Deletes/Removes the entity of type <code>getPrimaryClass()</code> in the EIS identified by
     * <code>entityId</code>.  Cascading deletes of other objects may be performed by the EIS if the
     * EIS is configured to do so.
     *
     * @param entityId the EIS id of the record to delete.
     *
     * @throws DataAccessException if there is an error accessing the EIS.
     */
    void deleteById( Serializable entityId ) throws DataAccessException;

    /**
     * Deletes <b>all</b> instances of type <code>getPrimaryClass()</code> found in the EIS.
     * Cascading deletes of other objects may be performed by the EIS if the EIS is configured to do
     * so.  <b>Only use this method if you're sure you want to delete all objects of the primary
     * type</b>.
     *
     * @throws DataAccessException if there is an error accessing the EIS.
     */
    void deleteAll() throws DataAccessException;

}
