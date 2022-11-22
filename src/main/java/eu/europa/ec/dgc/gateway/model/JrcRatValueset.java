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

package eu.europa.ec.dgc.gateway.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.ZonedDateTime;
import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.Data;

@Data
public class JrcRatValueset {

    @JsonProperty("id_device")
    @NotNull
    String idDevice;

    @JsonProperty("commercial_name")
    @NotNull
    String commercialName;

    @JsonProperty("manufacturer")
    @NotNull
    Manufacturer manufacturer;

    @JsonProperty("hsc_common_list")
    @NotNull
    Boolean hscCommonList;

    @JsonProperty("hsc_mutual_recognition")
    @NotNull
    Boolean hscMutualRecognition;

    @JsonProperty("last_updated")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss z")
    ZonedDateTime lastUpdated;

    @JsonProperty("hsc_list_history")
    List<HscListHistory> hscListHistory;

    @Data
    public static class HscListHistory {

        @JsonProperty("list_date")
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss z")
        @NotNull
        ZonedDateTime listDate;

        @JsonProperty("in_common_list")
        @NotNull
        Boolean inCommonList;

        @JsonProperty("in_mutual_recognition")
        @NotNull
        Boolean inMutualRecognition;
    }

    @Data
    public static class Manufacturer {

        @JsonProperty("id_manufacturer")
        @NotNull
        String id;

        @JsonProperty("name")
        @NotNull
        String name;

        @JsonProperty("country")
        @NotNull
        String country;

        @JsonProperty("website")
        @NotNull
        String website;
    }
}
