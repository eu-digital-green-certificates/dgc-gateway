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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import javax.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

@Service
@Configuration
@RequiredArgsConstructor
public class ValidationRuleSchemaProvider {

    private final DgcConfigProperties configProperties;

    @Getter
    private Schema validationRuleSchema;

    @PostConstruct
    void setup() throws FileNotFoundException {
        File schemaFile = ResourceUtils.getFile(configProperties.getValidationRuleSchema());

        validationRuleSchema = SchemaLoader.builder()
            .schemaJson(new JSONObject(new JSONTokener(new FileInputStream(schemaFile))))
            .draftV7Support()
            .build().load().build();
    }

}
