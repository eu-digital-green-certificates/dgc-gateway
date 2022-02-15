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

package eu.europa.ec.dgc.gateway.restapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;


@Schema(description = "Trusted refernece representation.")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TrustedReferenceDto {

    private String uuid;

    private String version;

    @Schema(description = "ISO 3166 2-Digit Country Code")
    @Length(min = 2, max = 2)
    @NotNull
    private String country;

    private ReferenceTypeDto type;

    private String service;

    private String thumbprint;

    private String name;

    private String sslPublicKey;

    private String contentType;

    private SignatureTypeDto signatureType;

    public enum ReferenceTypeDto {
        DCC,
        FHIR
    }

    public enum SignatureTypeDto {
        CMS,
        JWS,
        NONE
    }

}
