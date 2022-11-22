/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
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

package eu.europa.ec.dgc.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AssetManagerSynchronizeResponseDto {

    /**
     * Initialize Dto with values for embedded sub-classed.
     */
    public AssetManagerSynchronizeResponseDto(
        String status, int statusCode, String message, String path, String token) {
        Ocs.Data data = new Ocs.Data(statusCode, message, token, path);
        Ocs.Meta meta = new Ocs.Meta(status, statusCode, message);

        ocs = new Ocs(meta, data);
    }

    private Ocs ocs;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Ocs {

        private Meta meta;
        private Data data;

        @Getter
        @Setter
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Meta {
            private String status;
            private Integer statuscode;
            private String message;
        }

        @Getter
        @Setter
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Data {
            private Integer statusCode;
            private String statusMessage;
            private String token;
            private String path;
        }
    }
}
