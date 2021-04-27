package eu.europa.ec.dgc.gateway.repository;

import eu.europa.ec.dgc.gateway.entity.AuditEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepositorty extends JpaRepository<AuditEventEntity, Long> {
}
