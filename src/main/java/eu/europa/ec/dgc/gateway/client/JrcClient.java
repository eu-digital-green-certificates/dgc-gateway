/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 - 2022 T-Systems International GmbH and all other contributors
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

package eu.europa.ec.dgc.gateway.client;

import eu.europa.ec.dgc.gateway.model.JrcRatValueset;
import java.util.List;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(
    name = "jrcClient",
    url = "${dgc.jrc.url}",
    configuration = JrcClientConfig.class)
public interface JrcClient {

    /**
     * This method gets a the RAT values from JRC API.
     *
     * @return List of RAT values.
     */
    @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE
    )
    List<JrcRatValueset> downloadRatValues();
}
