package eu.europa.ec.dgc.gateway.repository;

import eu.europa.ec.dgc.gateway.entity.TrustedIssuerEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TrustedIssuerRepository extends JpaRepository<TrustedIssuerEntity, Long> {

    List<TrustedIssuerEntity> getAllByCountryIn(List<String> country);
}
