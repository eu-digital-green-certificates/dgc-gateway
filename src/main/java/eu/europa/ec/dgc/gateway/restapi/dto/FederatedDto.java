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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import javax.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class FederatedDto {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Gateway ID of the source gateway this entry origins from.")
    @Pattern(regexp = "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$")
    private String sourceGateway;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Globally Unique identifier for this entity.")
    @Pattern(regexp = "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$")
    private String uuid;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Domains this entry belongs to.")
    private String domain;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Version of this entity.")
    private Long version = 1L;

}
