package sugar.free.telesto.utils;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import java.util.HashMap;
import java.util.Map;

import sugar.free.telesto.R;
import sugar.free.telesto.TelestoApp;
import sugar.free.telesto.exceptions.AboutToDisconnectException;
import sugar.free.telesto.exceptions.BluetoothBondRemovedException;
import sugar.free.telesto.exceptions.ConnectionFailedException;
import sugar.free.telesto.exceptions.ConnectionLostException;
import sugar.free.telesto.exceptions.DisconnectedException;
import sugar.free.telesto.exceptions.RecoveryFailedException;
import sugar.free.telesto.exceptions.SatlPairingRejectedException;
import sugar.free.telesto.exceptions.SocketCreationFailedException;
import sugar.free.telesto.exceptions.TimeoutException;
import sugar.free.telesto.exceptions.app_layer_errors.MaximumNumberOfBolusTypeAlreadyRunningException;
import sugar.free.telesto.exceptions.app_layer_errors.NoActiveTBRToCanceLException;
import sugar.free.telesto.exceptions.app_layer_errors.NoActiveTBRToChangeException;
import sugar.free.telesto.exceptions.app_layer_errors.NoSuchBolusToCancelException;
import sugar.free.telesto.exceptions.app_layer_errors.PumpAlreadyInThatStateException;
import sugar.free.telesto.exceptions.app_layer_errors.PumpStoppedException;
import sugar.free.telesto.exceptions.app_layer_errors.RunModeNotAllowedException;

public class ExceptionTranslator {

    private static final Map<Class<? extends Exception>, Integer> TABLE = new HashMap<>();

    static {
        TABLE.put(AboutToDisconnectException.class, R.string.about_to_disconnect);
        TABLE.put(BluetoothBondRemovedException.class, R.string.bluetooth_bond_removed);
        TABLE.put(ConnectionFailedException.class, R.string.connection_failed);
        TABLE.put(ConnectionLostException.class, R.string.connection_lost);
        TABLE.put(DisconnectedException.class, R.string.disconnected);
        TABLE.put(RecoveryFailedException.class, R.string.recovery_failed);
        TABLE.put(SatlPairingRejectedException.class, R.string.pairing_rejected);
        TABLE.put(SocketCreationFailedException.class, R.string.socket_creation_failed);
        TABLE.put(TimeoutException.class, R.string.timeout);
        TABLE.put(MaximumNumberOfBolusTypeAlreadyRunningException.class, R.string.maximum_number_of_bolus_type_already_running);
        TABLE.put(NoActiveTBRToCanceLException.class, R.string.no_active_tbr_to_cancel);
        TABLE.put(NoActiveTBRToChangeException.class, R.string.no_active_tbr_to_change);
        TABLE.put(NoSuchBolusToCancelException.class, R.string.no_such_bolus_to_cancel);
        TABLE.put(PumpAlreadyInThatStateException.class, R.string.pump_already_in_that_state_exception);
        TABLE.put(PumpStoppedException.class, R.string.pump_stopped);
        TABLE.put(RunModeNotAllowedException.class, R.string.run_mode_not_allowed);
    }

    public static String getString(Exception exception) {
        Integer res = TABLE.get(exception.getClass());
        return res == null ? exception.getClass().getSimpleName() : TelestoApp.getInstance().getString(res);
    }

    public static void makeToast(Context context, Exception exception) {
        new Handler(Looper.getMainLooper()).post(() -> Toast.makeText(context, getString(exception), Toast.LENGTH_LONG).show());
    }
}
