/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.authc.support;

import org.jsecurity.authc.Account;

/**
 * An <tt>AggregateAccount</tt> is an <em>aggregation</em>, or <em>composition</em> of accounts from across multiple
 * <tt>Realm</tt>s.
 *
 * <p>This is useful in a multi-realm authentication configuration - the individual <tt>Account</tt>
 * objects obtained from each realm can be {@link #merge merged} into a single object that implements this
 * interface.  This single object can then be returned to the
 * {@link org.jsecurity.authc.Authenticator#authenticate Authenticator.authenticate()} caller, giving the
 * impression of a single underlying realm/data source.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface AggregateAccount extends Account {

    /**
     * Merges (adds) the specified Account data into this instance.
     * @param account the account whos data will be merged (added) into this instance.
     */
    void merge(Account account);

}
