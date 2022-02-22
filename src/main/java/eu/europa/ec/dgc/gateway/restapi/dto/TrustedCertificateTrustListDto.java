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
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Schema(
    name = "Trusted Certificate Trust List Item"
)
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TrustedCertificateTrustListDto extends FederatedDto {

    @Schema(description = "Base64 encoded Ceritficate")
    String certificate;

    @Schema(description = "Base64 encoded detached CMS.")
    String signature;

    @Schema(description = "Custom KID. If not provided the first 8 byte of certificate thumbprint will be used.")
    String kid;

    String group;

    String country;

    @Schema(description = "Additional properties which should be stored with the certificate.")
    Map<String, String> properties;
}
