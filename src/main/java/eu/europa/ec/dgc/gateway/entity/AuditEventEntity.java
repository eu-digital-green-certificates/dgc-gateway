package eu.europa.ec.dgc.gateway.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.time.ZonedDateTime;

@Getter
@Setter
@Entity
@Table(name = "audit_event")
@AllArgsConstructor
@NoArgsConstructor
public class AuditEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * Timestamp of the Record.
     */
    @Column(name = "timestamp", nullable = false)
    private ZonedDateTime createdAt = ZonedDateTime.now();

    /**
     * ISO 3166 Alpha-2 Country Code
     * (plus code "EU" for administrative European Union entries).
     */
    @Column(name = "country", nullable = false, length = 2)
    private String country;

    /**
     * uploader_sha256_fingerprint SHA256-fingerprint of the certificate
     */
    @Column(name = "uploader_sha256_fingerprint", nullable = false, length = 64)
    private String uploaderSha256Fingerprint;

    /**
     * uploader_sha256_fingerprint SHA256-fingerprint of the certificate
     */
    @Column(name = "authentication_sha256_fingerprint", nullable = false, length = 64)
    private String authenticationSha256Fingerprint;

    /**
     * ID of the event that was recorded.
     */
    @Column(name = "event", nullable = false, length = 64)
    private String event;

    /**
     * Description of the recoreded event.
     */
    @Column(name = "description", nullable = false, length = 64)
    private String description;

}
