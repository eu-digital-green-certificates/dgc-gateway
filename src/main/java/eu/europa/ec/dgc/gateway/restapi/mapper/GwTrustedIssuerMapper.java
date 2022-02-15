package eu.europa.ec.dgc.gateway.restapi.mapper;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedIssuerDto;
import java.util.List;
import org.mapstruct.Mapper;


@Mapper(componentModel = "spring")
public interface GwTrustedIssuerMapper {

    TrustedIssuerDto trustedIssuerEntityToTrustedIssuerDto(TrustedIssuerEntity trustedIssuer);

    List<TrustedIssuerDto> trustedIssuerEntityToTrustedIssuerDto(List<TrustedIssuerEntity> trustedIssuer);
}
