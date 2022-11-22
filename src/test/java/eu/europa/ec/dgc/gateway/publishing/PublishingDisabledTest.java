/*-
 * ---license-start
 * WHO Digital Documentation Covid Certificate Gateway Service / ddcc-gateway
 * ---
 * Copyright (C) 2022 T-Systems International GmbH and all other contributors
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

package eu.europa.ec.dgc.gateway.publishing;

import eu.europa.ec.dgc.gateway.client.AssetManagerClient;
import eu.europa.ec.dgc.gateway.client.AssetManagerClientConfig;
import eu.europa.ec.dgc.gateway.service.PublishingService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

@SpringBootTest(properties = {
    "dgc.publication.enabled=false"
})
@Slf4j
public class PublishingDisabledTest {

    @Autowired
    ApplicationContext applicationContext;

    @ParameterizedTest
    @ValueSource(classes = {PublishingService.class, AssetManagerClientConfig.class, AssetManagerClient.class})
    void testBeansAreNotCreated(Class<?> clazz) {
        Assertions.assertThrows(NoSuchBeanDefinitionException.class,
            () -> applicationContext.getAutowireCapableBeanFactory().getBean(clazz));
    }

}
