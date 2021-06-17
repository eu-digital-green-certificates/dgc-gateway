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
