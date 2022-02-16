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
import javax.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;


@Schema(description = "Trusted refernece representation.")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TrustedReferenceDto {

    @Schema(description = "Unique Identifier of the Trusted Reference", format = "UUID")
    @Pattern(regexp = "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$")
    private String uuid;

    @Schema(description = "Version of the Trusted Reference")
    @NotNull
    private String version;

    @Schema(description = "ISO 3166 2-Digit Country Code")
    @Length(min = 2, max = 2)
    @NotNull
    private String country;

    @Schema(description = "Type of the Trusted Reference (DCC,FHIR)")
    @NotNull
    private ReferenceTypeDto type;

    @Schema(description = "Service of the Trusted Reference")
    @NotNull
    @Length(min = 1, max = 1024)
    private String service;

    @Schema(description = "SHA256 Hash of the Trusted Reference")
    @NotNull
    @Length(min = 1, max = 64)
    private String thumbprint;

    @Schema(description = "Name of the Service")
    @NotNull
    @Length(min = 1, max = 512)
    private String name;

    @Schema(description = "SSL Certificate of the endpoint")
    @NotNull
    @Length(min = 1, max = 2048)
    private String sslPublicKey;

    @Schema(description = "MIME Type of Content")
    @NotNull
    @Length(min = 1, max = 512)
    private String contentType;

    @Schema(description = "Signature type (NONE|JWS|CMS)")
    @NotNull
    private SignatureTypeDto signatureType;

    @Schema(description = "Any version String of the trusted reference")
    @NotNull
    private String referenceVersion;

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
