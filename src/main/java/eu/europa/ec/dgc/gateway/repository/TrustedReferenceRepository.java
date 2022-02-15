package eu.europa.ec.dgc.gateway.repository;

import eu.europa.ec.dgc.gateway.entity.TrustedReferenceEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


public interface TrustedReferenceRepository extends JpaRepository<TrustedReferenceEntity, Long> {

    @Modifying
    @Query("DELETE FROM TrustedReferenceEntity r WHERE r.uuid = :uuid")
    int deleteByUuid(@Param("uuid") String uuid);

    Optional<TrustedReferenceEntity> getByUuid(String uuid);

    List<TrustedReferenceEntity> getAllByCountry(String country);

}
