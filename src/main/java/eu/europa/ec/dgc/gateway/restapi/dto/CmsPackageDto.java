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
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Schema(name = "CmsPackage")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CmsPackageDto {

    @Schema(description = "CMS containing the signed String or certificate")
    private String cms;

    @Schema(description = "Internal ID of the package")
    private Long entityId;

    @Schema(description = "Type of the CMS package")
    private CmsPackageTypeDto type;

    public enum CmsPackageTypeDto {
        DSC,
        REVOCATION_LIST,
        VALIDATION_RULE
    }
}
