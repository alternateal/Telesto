package sugar.free.telesto.exceptions.app_layer_errors;

public class PumpAlreadyInThatStateException extends AppLayerErrorException {

    private static final long serialVersionUID = 1;

    public PumpAlreadyInThatStateException(int errorCode) {
        super(errorCode);
    }
}
