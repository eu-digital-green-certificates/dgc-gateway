package eu.europa.ec.dgc.gateway.exception;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Getter
@Setter
public class DgcgResponseException extends ResponseStatusException {

    private String code;
    private String details;
    private String sentValues;
    private String problem;

    /**
     * One Arg constructor for DgcgResponseException.
     *
     * @param status the HTTP Status.
     */
    public DgcgResponseException(HttpStatus status) {
        super(status);
    }

    /**
     * All Args constructor for DgcgResponseException.
     *
     * @param status the HTTP Status.
     * @param code the error code.
     * @param details the details of the problem.
     * @param sentValues the values sent to cause the error.
     * @param problem   short problem description.
     */
    public DgcgResponseException(HttpStatus status,String code,String problem,String sentValues,String details) {
        super(status);
        this.code = code;
        this.details = details;
        this.sentValues = sentValues;
        this.problem = problem;
    }
}