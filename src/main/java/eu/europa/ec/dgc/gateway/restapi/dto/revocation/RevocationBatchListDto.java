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

package eu.europa.ec.dgc.gateway.restapi.dto.revocation;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Pattern;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

@Data
public class RevocationBatchListDto {

    @Schema(description = "The result is limited by default to 10K. If the flag ‘more’ is set to true, "
        + "the response indicates that more batches are available for download. "
        + "To download more items the client must set the If-Modified-Since header")
    private Boolean more;

    @Schema(description = "The List of batches available since the provided date")
    private List<RevocationBatchListItemDto> batches;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class RevocationBatchListItemDto {

        @Schema(description = "Unique Identifier of the Batch", format = "UUID")
        @Pattern(regexp = "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$")
        private String batchId;

        @Schema(description = "2-Digit ISO 3166 Country Code")
        @Length(min = 2, max = 2)
        private String country;

        @Schema(description = "Date corresponding to the lastEvent")
        private ZonedDateTime date;

        @Schema(description = "When true, the entry will be finally removed from the query results after 7 days.")
        private Boolean deleted;
    }
}
