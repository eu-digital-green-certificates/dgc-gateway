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

package eu.europa.ec.dgc.gateway.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class DgcgResponseException extends RuntimeException {

    private final String code;
    private final String details;
    private final String sentValues;
    private final String problem;
    private final HttpStatus status;

    /**
     * All Args constructor for DgcgResponseException.
     *
     * @param status     the HTTP Status.
     * @param code       the error code.
     * @param details    the details of the problem.
     * @param sentValues the values sent to cause the error.
     * @param problem    short problem description.
     */
    public DgcgResponseException(HttpStatus status, String code, String problem, String sentValues, String details) {
        this.status = status;
        this.code = code;
        this.details = details;
        this.sentValues = sentValues;
        this.problem = problem;
    }
}
