package eu.europa.ec.dgc.gateway.restapi.mapper;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface GwTrustedIssuerMapper {

    TrustedIssuerDto trustedIssuerEntityToTrustedIssuerDto(TrustedIssuerEntity trustedIssuer);

    List<TrustedIssuerDto> trustedIssuerEntityToTrustedIssuerDto(List<TrustedIssuerEntity> trustedIssuer);
}
