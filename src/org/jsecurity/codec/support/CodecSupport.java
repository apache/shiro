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
package org.jsecurity.codec.support;

import org.jsecurity.codec.CodecException;

import java.io.UnsupportedEncodingException;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class CodecSupport {

    public static final String PREFERRED_ENCODING = "UTF-8";

    public static byte[] toBytes( char[] chars ) {
        return toBytes( new String( chars ) );
    }

    public static byte[] toBytes( char[] chars, String encoding ) {
        return toBytes( new String( chars ), encoding );
    }

    public static byte[] toBytes( String source ) {
        return toBytes( source, PREFERRED_ENCODING );
    }

    public static byte[] toBytes( String source, String encoding ) {
        try {
            return source.getBytes( encoding );
        } catch (UnsupportedEncodingException e) {
            String msg = "Unable to convert source [" + source + "] to byte array using " +
                "encoding '" + encoding + "'";
            throw new CodecException( msg, e );
        }
    }

    public static String toString( byte[] bytes ) {
        return toString( bytes, PREFERRED_ENCODING );
    }

    public static String toString( byte[] bytes, String encoding ) {
        try {
            return new String( bytes, encoding );
        } catch (UnsupportedEncodingException e) {
            String msg = "Unable to convert byte array to String with encoding '" + encoding + "'.";
            throw new CodecException( msg, e );
        }
    }

    public static char[] toChars( byte[] bytes ) {
        return toChars( bytes, PREFERRED_ENCODING );
    }

    public static char[] toChars( byte[] bytes, String encoding ) {
        return toString( bytes, encoding ).toCharArray();
    }

    protected byte[] toBytes( Object o ) {
        if ( o instanceof byte[] ) {
            return (byte[])o;
        } else if ( o instanceof char[] ) {
            return toBytes( (char[])o );
        } else if ( o instanceof String ) {
            return toBytes( (String)o );
        } else {
            return objectToBytes( o );
        }
    }

    // When the toBytes(object) method calls this one, the object argument won't be a byte[], char[] or String
    // implementation authors should cast for something else.  This default implementation
    // throws an exception immediately and it is expected that subclass authors would override it.
    protected byte[] objectToBytes( Object o ) {
        String msg = "The " + getClass().getName() + " implementation only supports " +
                "credentials of type byte[], char[] or String.";
        throw new IllegalArgumentException( msg );
    }
}
