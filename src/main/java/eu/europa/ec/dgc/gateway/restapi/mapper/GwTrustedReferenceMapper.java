package eu.europa.ec.dgc.gateway.restapi.mapper;

import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustedReferenceDto;
import java.util.List;
import org.mapstruct.Mapper;


@Mapper(componentModel = "spring")
public interface GwTrustedReferenceMapper {

    TrustedReferenceDto trustedReferenceEntityToTrustedReferenceDto(TrustedReferenceEntity trustedReference);

    List<TrustedReferenceDto> trustedReferenceEntityToTrustedReferenceDto(
            List<TrustedReferenceEntity> trustedReference);
}
