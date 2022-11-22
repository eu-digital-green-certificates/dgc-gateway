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

package eu.europa.ec.dgc.gateway.restapi.mapper;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.ec.dgc.gateway.entity.FederationGatewayEntity;
import eu.europa.ec.dgc.gateway.entity.SignerInformationEntity;
import eu.europa.ec.dgc.gateway.model.TrustList;
import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.model.TrustedCertificateTrustList;
import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustListDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedCertificateTrustListDto;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
@Slf4j
public abstract class GwTrustListMapper {

    @Mapping(source = "certificateType", target = "domain")
    @Mapping(target = "sourceGateway", ignore = true)
    @Mapping(target = "uuid", ignore = true)
    @Mapping(target = "version", ignore = true)
    public abstract TrustListDto trustListToTrustListDto(TrustList trustList);

    public abstract List<TrustListDto> trustListToTrustListDto(List<TrustList> trustList);

    public abstract TrustListType certificateTypeDtoToTrustListType(CertificateTypeDto certificateTypeDto);

    public abstract List<TrustedCertificateTrustListDto> trustListToDto(
        List<TrustedCertificateTrustList> trustList, @Context ObjectMapper objectMapper);

    public abstract TrustedCertificateTrustListDto map(
        TrustedCertificateTrustList trustListItem, @Context ObjectMapper objectMapper);

    @Mapping(source = "certificateType", target = "group")
    @Mapping(source = "rawData", target = "certificate")
    public abstract TrustedCertificateTrustListDto map(
        SignerInformationEntity entity, @Context ObjectMapper objectMapper);

    /**
     * Map Federation Gateway Entity to String.
     */
    public String map(FederationGatewayEntity gatewayEntity) {
        if (gatewayEntity == null) {
            return null;
        } else {
            return gatewayEntity.getGatewayId();
        }
    }

    /**
     * Map JSON String to properties Map.
     */
    public Map<String, String> mapMap(String json, @Context ObjectMapper objectMapper) {
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, String>>() {
            });
        } catch (Exception e) {
            log.error("Failed To Map TrustedCertificate Entity to DTO.");
            return null;
        }
    }
}
