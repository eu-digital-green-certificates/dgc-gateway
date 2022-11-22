/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.gateway.utils;

import java.util.Collections;
import java.util.List;

public class ListUtils {

    private ListUtils() {
    }

    /**
     * Returns a sublist of a list of objects based on page index and size.
     *
     * @param list list for sublist.
     * @param page zero-based page index, must NOT be negative.
     * @param size number of items in a page to be returned, must be greater than 0.
     * @return sublist of a list of objects.
     */
    public static <T> List<T> getPage(List<T> list, int page, int size) {

        if (page < 0) {
            throw new IllegalArgumentException("Page index must not be less than zero!");
        }
        if (size <= 0) {
            throw new IllegalArgumentException("Page size must not be less than one!");
        }

        int fromIndex = (page) * size;
        if (list == null || list.size() < fromIndex) {
            return Collections.emptyList();
        }
        return list.subList(fromIndex, Math.min(fromIndex + size, list.size()));
    }

}
