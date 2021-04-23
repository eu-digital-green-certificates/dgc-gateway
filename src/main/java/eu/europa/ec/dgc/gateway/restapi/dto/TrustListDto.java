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
import java.time.ZonedDateTime;

@Schema(
    name = "TrustList",
    type = "object",
    example = "{\n"
        + "\"id\":\"32434-234234-234-2342424-23434\",\n"
        + "\"timestamp\":\"2021-03-05 14:00:25+02:00\",\n"
        + "\"country\":\"DE\",\n"
        + "\"certificateType\":\"ISSUER\",\n"
        + "\"thumbprint\":\"69c697c045b4cdaa441a28af0ec1bb4128153b9ddc796b66bfa04b02ea3e103e\",\n"
        + "\"signature\":\"o53CbAa77LyIMFc5Gz+B2Jc275Gdg/SdLayw7gx0GrTcinR95zfTLr8nNHgJMYlX3rD8Y11zB/Osyt0"
        + " ... W+VIrYRGSEmgjGy2EwzvA5nVhsaA+/udnmbyQw9LjAOQ==\",\n"
        + "\"rawData\":\"-----BEGIN CERTIFICATE-----\\nMIICyDCCAbCgAwIBAgIGAXR3DZUUMA0GCSqGSIb3DQEBBQUAMBwxCzAJB"
        + " ... Jpux30QRhsNZwkmEYSbRv+vp5/obgH1mL5ouoV5I=\\n-----END CERTIFICATE-----\\n\"\n"
        + "}"
)
public class TrustListDto {

    private String id;

    private ZonedDateTime timestamp;

    private String country;

    private CertificateTypeDto certificateType;

    private String thumbprint;

    private String signature;

    private String rawData;

}
