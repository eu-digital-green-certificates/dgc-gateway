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

package eu.europa.ec.dgc.gateway.restapi.dto.did;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import lombok.Data;
import lombok.experimental.SuperBuilder;

@Data
public class DidTrustListEntryDto {

    private String id;

    private String type;

    private String controller;

    private PublicKeyJwk publicKeyJwk;

    @Data
    @SuperBuilder
    private abstract static class PublicKeyJwk {
        @JsonProperty("kty")
        private String keyType;

        @JsonProperty("x5c")
        private List<String> encodedX509Certificates;
    }

    @Data
    @SuperBuilder
    public static class EcPublicKeyJwk extends PublicKeyJwk {

        @JsonProperty("crv")
        private String curve;

        @JsonProperty("x")
        private String valueX;

        @JsonProperty("y")
        private String valueY;
    }

}
