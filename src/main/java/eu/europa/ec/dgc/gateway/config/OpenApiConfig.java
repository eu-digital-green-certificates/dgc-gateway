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

package eu.europa.ec.dgc.gateway.config;

import eu.europa.ec.dgc.gateway.restapi.dto.ValidationRuleDto;
import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.core.converter.ResolvedSchema;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.security.SecurityScheme;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@RequiredArgsConstructor
public class OpenApiConfig {

    private final Optional<BuildProperties> buildProperties;

    private final DgcConfigProperties configProperties;

    private final Environment environment;

    public static final String SECURITY_SCHEMA_HASH = "Authentication Certificate Hash";
    public static final String SECURITY_SCHEMA_DISTINGUISH_NAME = "Authentication Certificate Distinguish Name";

    @Bean
    OpenAPI openApiInfo() {
        String version;

        if (buildProperties.isPresent()) {
            version = buildProperties.get().getVersion();
        } else {
            version = "Development Build";
        }

        Components components = new Components();

        // Add authorization if "local" Profile is enabled.
        List<String> activeProfiles = Arrays.asList(environment.getActiveProfiles());
        if (activeProfiles.contains("local")) {
            components = new Components()
                .addSecuritySchemes(SECURITY_SCHEMA_HASH, new SecurityScheme()
                    .type(SecurityScheme.Type.APIKEY)
                    .in(SecurityScheme.In.HEADER)
                    .name(configProperties.getCertAuth().getHeaderFields().getThumbprint())
                    .description("SHA256 Hash of Authentication Certificate (HEX encoded, "
                        + "e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"))
                .addSecuritySchemes(SECURITY_SCHEMA_DISTINGUISH_NAME, new SecurityScheme()
                    .type(SecurityScheme.Type.APIKEY)
                    .in(SecurityScheme.In.HEADER)
                    .name(configProperties.getCertAuth().getHeaderFields().getDistinguishedName())
                    .description(SECURITY_SCHEMA_DISTINGUISH_NAME
                        + "Should contain at least country property. (e.g. C=EU)"));
        }

        ResolvedSchema validationRuleSchema = ModelConverters.getInstance().resolveAsResolvedSchema(
            new AnnotatedType(ValidationRuleDto.class).resolveAsRef(false));

        ArraySchema validationRuleArraySchema = new ArraySchema();
        validationRuleArraySchema.setItems(validationRuleSchema.schema);

        components.addSchemas(validationRuleSchema.schema.getName(), validationRuleSchema.schema);
        components.addSchemas("ValidationRuleDownloadResponse",
            new ObjectSchema().additionalProperties(validationRuleArraySchema));

        return new OpenAPI()
            .info(new Info()
                .version(version)
                .title("Digital Documentation Covid Certificate Gateway")
                .description("The API defines how to exchange verification information for Digital Covid Certificates.")
                .license(new License()
                    .name("Apache 2.0")
                    .url("http://www.apache.org/licenses/LICENSE-2.0")))
            .components(components);
    }
}
