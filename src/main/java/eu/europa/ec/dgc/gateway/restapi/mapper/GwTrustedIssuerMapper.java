package eu.europa.ec.dgc.gateway.restapi.mapper;


import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "spring")
public interface GwTrustedIssuerMapper {

    @Mapping(source = "createdAt", target = "timestamp")
    @Mapping(source = "urlType", target = "type")
    TrustedIssuerDto trustedIssuerEntityToTrustedIssuerDto(TrustedIssuerEntity trustedIssuer);

    @Mapping(source = "timestamp", target = "createdAt")
    List<TrustedIssuerDto> trustedIssuerEntityToTrustedIssuerDto(List<TrustedIssuerEntity> trustedIssuer);
}
