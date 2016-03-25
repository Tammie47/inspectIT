package info.novatec.inspectit.util;

/**
 * Exception to wrap all Exceptions thrown in the Permutation Class.
 * 
 * @author Andreas Herzog
 *
 */
public class PermutationException extends Exception {
	/**
	 * The generated serialVersionUID.
	 */
	private static final long serialVersionUID = -6993839937433771034L;
	
	/**
	 * This reason represents the exception message.
	 */
	private final String reason;
	
	/**
	 * Constructor.
	 * 
	 * @param reason PermutationException(e.getClass().getName() + " - " +  e.getMessage())
	 * 			for good readability.
	 */
	public PermutationException(String reason) {
		super(reason);
		this.reason = reason;
	}
	
	@Override
	public String getMessage() {
		return "PermutationException: " + reason;
	}

}
