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
package org.jsecurity.samples.sprhib.entity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;

/**
 * Root parent class for all persistent object entities.
 *
 * <p><b>NOTE:</b>  Subclasses should <b>always</b> provide a unique
 * onEquals() and hashCode() implementation and these should <em>not</em> use
 * the {@link #getId id} property.  Always keep in mind the subclass' 'business keys' aka 'natural keys'
 * when implementing these two methods.
 *
 * <p>This class was borrowed from the <a href="http://code.google.com/p/pojodm">PojoDM Project</a>'s
 * <a href="http://code.google.com/p/pojodm/source/browse/trunk/src/org/pojodm/entity/Entity.java">Entity.java</a>
 * for a quick kickstart.</p>
 *
 * @author Les Hazlewood
 */
public abstract class Entity implements Identifiable, Serializable, Cloneable {

    protected transient final Log log = LogFactory.getLog( getClass() );

    /**
     * RDBMS Primary key, aka 'surrogate key'.  <code>Long</code> surrogate keys are best
     * for RDBMS performance (for many reasons that can't be expanded on here)
     * But, every single table should _always_ have a 'business key' or 'natural key' - a unique
     * constraint across one or more columns that guarantee row duplicates will
     * never occur. A <code>null</code> value means the object hasn't been persisted to the RDBMS
     */
    protected Long id = null;

    /**
     * Used for optimistic locking to ensure two threads (even across different machines)
     * don't simultaneously overwrite entity state.  This propert is not necessarily used by all subclasses, but
     * it is pretty much required if in a high-concurrency environment and/or if using distributed
     * caching in a cluster.   It (and its corresponding mutator methods) is not called
     * 'version' to prevent eliminating that name from subclasses should the business
     * domain naming conventions require it.  Also 'entityVersion' is self-documenting
     * and leaves little room for incorrect interpretation.
     */
    protected int entityVersion = -1;

    public Entity() {
    }

    public Long getId() {
        return this.id;
    }

    /**
     * <p>Should <em>never</em> be called directly.  Only via JPA or Hibernate or other EIS framework, since
     * they get the ID from the RDBMS directly.</p>
     *
     * <p>This method can be removed entirely if the EIS framework supports setting the ID property
     * directly (e.g. through reflection).  Hibernate does support this, it is called 'property access'.</p>
     * 
     * @param id the entity id
     */
    public void setId(Long id) {
        this.id = id;
    }

    public int getEntityVersion() {
        return this.entityVersion;
    }

    /**
     * For the same reasons as the setId() method, this should only be called by a
     * framework and never directly.  Can be removed if the framework supports property access.
     * 
     * @param entityVersion the entity version number
     */
    public void setEntityVersion(int entityVersion) {
        this.entityVersion = entityVersion;
    }

    /**
     * This method is declared final and does a lot of performance optimization:
     *
     * <p>It delegates the actual "equals" check to subclasses via the onEquals method, but
     * it will only do so if the object for equality comparison is</p>
     *
     * <ol>
     * <li>not the same memory location as the current object (fast sanity check)</li>
     * <li>is <code>instanceof</code> Entity</li>
     * <li>Does not have the same id() property</li>
     * </ol>
     *
     * <p>#3 is important:  this is because if two different entities have the ID property
     * already populated, then they have already been inserted in the database, and
     * because of unique constraints on the database (i.e. your 'business key'), you
     * can <em>guarantee</em> that the objects are not the same and there is no need
     * to incur attribute-based comparisons for equals() checks.</p>
     *
     * <p>This little technique is a massive performance improvement given the number of times
     * equals checks happen in most applications.</p>
     */
    public final boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof Entity) {
            Entity e = (Entity) o;
            Long thisId = getId();
            Long otherId = e.getId();
            if (thisId != null && otherId != null) {
                return thisId.equals(otherId) && getClass().equals( e.getClass() );
            } else {
                return onEquals(e);
            }
        }

        return false;
    }

    /**
     * Subclasses must do an equals comparison based on business keys, aka 'natural keys' here.  Do <em>NOT</em> use
     * the {@link #getId id} property in these checks.
     * 
     * @param e the Entity to check for &quot;business&quot; equality based on natural keys.
     *
     * @return <code>true</code> if the specified Entity is naturally equal to this Entity, <code>false</code> otherwise.
     */
    public abstract boolean onEquals(Entity e);

    public abstract int hashCode();

    /**
     * If children classes override this method they must always call super.clone() to get the object
     * with which they manipulate further to clone remaining attributes.  Never acquire
     * the cloned object directly via 'new' operator (this is true in Java for any class - it is not special to
     * this Entity class).
     */
    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {

        Entity e;
        try {
            e = (Entity) super.clone();
        } catch (CloneNotSupportedException neverHappens) {
            // Should _never_ happen since this class is Cloneable and
            // a direct subclass of Object
            throw new InternalError("Unable to clone object of type [" + getClass().getName() + "]");
        }

        e.setId(null);
        e.setEntityVersion(-1);
        return e;
    }

    /**
     * Returns a StringBuffer representing the toString function of the class implementation. This
     * should be overridden by all children classes to represent the object in a meaningful String format.
     *
     * @return a <tt>StringBuffer</tt> reperesenting the <tt>toString</tt> value of this object.
     */
    public StringBuffer toStringBuffer() {
        return new StringBuffer(super.toString());
    }

    /**
     * Returns toStringBuffer().toString().  Declared as 'final' to require subclasses to override
     * the {@link #toStringBuffer()} method, a cleaner and better performing mechanism for toString();
     *
     * @return toStringBuffer().toString()
     */
    public final String toString() {
        return toStringBuffer().toString();
    }
}



