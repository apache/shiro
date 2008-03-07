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
package org.jsecurity.codec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.UnsupportedEncodingException;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class CodecSupport {
    
    protected transient final Log log = LogFactory.getLog( getClass() );

    public static final String PREFERRED_ENCODING = "UTF-8";

    public static byte[] toBytes( char[] chars ) {
        return toBytes( new String( chars ), PREFERRED_ENCODING );
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

    /**
     * Converts the specified Object into a byte array.
     *
     * <p>If the argument is a <tt>byte[]</tt>, <tt>char[]</tt>, or <tt>String</tt> it will be converted
     * automatically and returned.</tt>
     *
     * <p>If the argument is anything other than these three types, it is passed to the
     * {@link #objectToBytes(Object) objectToBytes} method which must be overridden by subclasses.
     * @param o the Object to convert into a byte array
     * @return a byte array representation of the Object argument.
     */
    protected byte[] toBytes( Object o ) {
        if ( o == null ) {
            String msg = "Argument for byte conversion cannot be null.";
            throw new IllegalArgumentException( msg );
        }
        if ( o instanceof byte[] ) {
            return (byte[])o;
        } else if (o instanceof char[] ) {
            return toBytes( (char[])o );
        } else if (o instanceof String ) {
            return toBytes( (String)o );
        } else {
            return objectToBytes( o );
        }
    }

    /**
     * Converts the specified Object into a String.
     *
     * <p>If the argument is a <tt>byte[]</tt>, <tt>char[]</tt>, or <tt>String</tt> it will be converted
     * automatically and returned.</tt>
     *
     * <p>If the argument is anything other than these three types, it is passed to the
     * {@link #objectToString(Object) objectToString} method which must be overridden by subclasses.
     * @param o the Object to convert into a byte array
     * @return a byte array representation of the Object argument.
     */
    protected String toString( Object o ) {
        if ( o == null ) {
            String msg = "Argument for String conversion cannot be null.";
            throw new IllegalArgumentException( msg );
        }
        if ( o instanceof byte[] ) {
            return toString( (byte[])o );
        } else if (o instanceof char[] ) {
            return new String( (char[])o );
        } else if (o instanceof String ) {
            return (String)o;
        } else {
            return objectToString( o );
        }
    }

    /**
     * Default implementation throws a CodecException immediately since it can't infer how to convert the Object
     * to a byte array.  This method must be overridden by subclasses if anything other than the three default
     * types (listed in the {@link #toBytes(Object) toBytes(Object)} JavaDoc) are to be converted to a byte array.
     *
     * @param o the Object to convert to a byte array.
     * @return a byte array representation of the Object argument.
     */
    protected byte[] objectToBytes( Object o ) {
        String msg = "The " + getClass().getName() + " implementation only supports conversion to " +
            "byte[] if the source is of type byte[], char[] or String.  The instance provided as a method " +
            "argument is of type [" + o.getClass().getName() + "].  If you would like to convert " +
            "this argument type to a byte[], you can 1) convert the argument to a byte[], char[] or String " +
            "yourself and then use that as the method argument or 2) subclass " + getClass().getName() +
            " and override the objectToBytes(Object o) method.";
        throw new CodecException( msg );
    }

    /**
     * Default implementation merely returns <code>objectArgument.toString()</code>.  Subclasses can override this
     * method for different mechanisms of converting an object to a String.
     *
     * @param o the Object to convert to a byte array.
     * @return a String representation of the Object argument.
     */
    protected String objectToString( Object o ) {
        return o.toString();
    }
}
