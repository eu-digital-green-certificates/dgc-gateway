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

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.ZonedDateTime;
import lombok.Getter;
import lombok.Setter;

@Schema(
    name = "TrustList",
    type = "object"
)
@Getter
@Setter
public class TrustListDto {

    @Schema(example = "qroU+hDDovs=")
    private String kid;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ssXXX")
    private ZonedDateTime timestamp;

    @Schema(example = "EU")
    private String country;

    private CertificateTypeDto certificateType;

    @Schema(example = "aaba14fa10c3a2fb441a28af0ec1bb4128153b9ddc796b66bfa04b02ea3e103e")
    private String thumbprint;

    @Schema(example = "o53CbAa77LyIMFc5Gz+B2Jc275Gdg/SdLayw7gx0GrTcinR95zfTLr8nNHgJMYlX3rD8Y11zB/Osyt0 ..."
        + " W+VIrYRGSEmgjGy2EwzvA5nVhsaA+/udnmbyQw9LjAOQ==")
    private String signature;

    @Schema(example = "MIICyDCCAbCgAwIBAgIGAXR3DZUUMA0GCSqGSIb3DQEBBQUAMBwxCzAJB ..."
        + " Jpux30QRhsNZwkmEYSbRv+vp5/obgH1mL5ouoV5I=")
    private String rawData;

}
