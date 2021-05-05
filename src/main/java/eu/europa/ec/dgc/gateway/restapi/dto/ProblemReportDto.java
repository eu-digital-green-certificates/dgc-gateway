/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
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
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(
    name = "ProblemReport",
    type = "object"
)
@Data
@AllArgsConstructor
public class ProblemReportDto {

    @Schema(example = "0x001")
    private String code;

    @Schema(example = "Signer Certificate is unknown.")
    private String problem;

    @Schema(example = "Certificate Thumbprint: 2342424f24c242f42f4b24...")
    private String sendValue;

    @Schema(example = "Use a known upload certificate to upload signer information.")
    private String details;
}
