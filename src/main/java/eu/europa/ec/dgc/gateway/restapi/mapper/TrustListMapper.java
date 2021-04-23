package eu.europa.ec.dgc.gateway.restapi.mapper;

import eu.europa.ec.dgc.gateway.model.TrustList;
import eu.europa.ec.dgc.gateway.model.TrustListType;
import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import eu.europa.ec.dgc.gateway.restapi.dto.TrustListDto;
import java.util.List;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TrustListMapper {

    TrustListDto trustListToTrustListDto(TrustList trustList);

    List<TrustListDto> trustListToTrustListDto(List<TrustList> trustList);

    TrustListType certificateTypeDtoToTrustListType(CertificateTypeDto certificateTypeDto);
}
