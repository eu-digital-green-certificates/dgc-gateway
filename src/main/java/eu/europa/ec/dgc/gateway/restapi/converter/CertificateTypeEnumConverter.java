package eu.europa.ec.dgc.gateway.restapi.converter;

import eu.europa.ec.dgc.gateway.restapi.dto.CertificateTypeDto;
import java.util.Locale;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class CertificateTypeEnumConverter implements Converter<String, CertificateTypeDto> {

    /**
     * Converts a string into {@link CertificateTypeDto} (case insensitive).
     *
     * @param source String to convert
     * @return value of {@link CertificateTypeDto}
     */
    @Override
    public CertificateTypeDto convert(String source) {
        return CertificateTypeDto.valueOf(source.toUpperCase(Locale.ROOT));
    }
}
