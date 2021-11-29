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

package eu.europa.ec.dgc.gateway.restapi.dto.revocation;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.ZonedDateTime;
import java.util.List;
import javax.validation.constraints.Pattern;
import lombok.Data;

@Data
public class BatchListDto {

    @Schema(description = "The result is limited by default to 10K. If the flag ‘more’ is set to true, "
        + "the response indicates that more batches are available for download. "
        + "To download more items the client must set the If-Modified-Since header")
    private Boolean more;

    @Schema(description = "The List of batches available since the provided date")
    private List<BatchListItemDto> batches;

    @Data
    public static class BatchListItemDto {

        @Schema(description = "Unique Identifier of the Batch", format = "UUID")
        @Pattern(regexp = "^[0-9a-f]{8}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{4}\\b-[0-9a-f]{12}$")
        private String batchId;

        @Schema(description = "2-Digit ISO 3166 Country Code")
        private String country;

        @Schema(description = "Date corresponding to the lastEvent")
        private ZonedDateTime date;

        @Schema(description = "Last event that has happened to the batch item")
        private BatchListItemEventDto lastEvent;
    }

    public enum BatchListItemEventDto {

        @Schema(description = "Batch was deleted by uploader. Will be finally deleted within a few days.")
        DELETED,

        @Schema(description = "The batch was resigned by the uploader.")
        RESIGNED,

        @Schema(description = "The batch was uploaded by the member state.")
        ADDED
    }
}
