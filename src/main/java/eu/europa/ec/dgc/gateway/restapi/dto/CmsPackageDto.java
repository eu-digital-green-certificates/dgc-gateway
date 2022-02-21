package eu.europa.ec.dgc.gateway.restapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "CmsPackage")
@Data
@AllArgsConstructor
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
