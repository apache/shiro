package org.jsecurity.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;

/**
 * Static helper class for use dealing with Arrays.
 */
public class CollectionUtils {

  public static <E> LinkedHashSet<E> newLinkedHashSet(E... elements) {
    LinkedHashSet<E> set = new LinkedHashSet<E>(elements.length * 4 / 3 + 1);
    Collections.addAll(set, elements);
    return set;
  }

    public static <E> ArrayList<E> newArrayList(E... elements) {
      // Avoid integer overflow when a large array is passed in
      int capacity = computeArrayListCapacity(elements.length);
      ArrayList<E> list = new ArrayList<E>(capacity);
      Collections.addAll(list, elements);
      return list;
    }

    static int computeArrayListCapacity(int arraySize) {
      return (int) Math.min(5L + arraySize + (arraySize / 10), Integer.MAX_VALUE);
    }


}
