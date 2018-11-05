package sugar.free.telesto.services.connection_service;

import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Binder;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import androidx.annotation.Nullable;
import sugar.free.telesto.TelestoApp;
import sugar.free.telesto.activities.LauncherActivity;
import sugar.free.telesto.activities.SetupActivity;
import sugar.free.telesto.descriptors.TelestoState;
import sugar.free.telesto.exceptions.AboutToDisconnectException;
import sugar.free.telesto.exceptions.BluetoothBondRemovedException;
import sugar.free.telesto.exceptions.ConnectionFailedException;
import sugar.free.telesto.exceptions.ConnectionLostException;
import sugar.free.telesto.exceptions.DisconnectedException;
import sugar.free.telesto.exceptions.OrbitalException;
import sugar.free.telesto.exceptions.SatlPairingRejectedException;
import sugar.free.telesto.exceptions.SocketCreationFailedException;
import sugar.free.telesto.exceptions.TimeoutException;
import sugar.free.telesto.exceptions.app_layer_errors.InvalidServicePasswordException;
import sugar.free.telesto.parser.app_layer.AppLayerMessage;
import sugar.free.telesto.parser.app_layer.configuration.CloseConfigurationWriteSessionMessage;
import sugar.free.telesto.parser.app_layer.configuration.OpenConfigurationWriteSessionMessage;
import sugar.free.telesto.parser.app_layer.configuration.WriteConfigurationBlockMessage;
import sugar.free.telesto.parser.app_layer.connection.ActivateServiceMessage;
import sugar.free.telesto.parser.app_layer.connection.DisconnectMessage;
import sugar.free.telesto.parser.app_layer.connection.ServiceChallengeMessage;
import sugar.free.telesto.parser.ids.ServiceIDs;
import sugar.free.telesto.parser.satl.ConnectionRequest;
import sugar.free.telesto.parser.satl.KeyRequest;
import sugar.free.telesto.parser.satl.PairingStatus;
import sugar.free.telesto.parser.satl.SatlMessage;
import sugar.free.telesto.parser.satl.SynRequest;
import sugar.free.telesto.parser.satl.VerifyConfirmRequest;
import sugar.free.telesto.parser.utils.ByteBuf;
import sugar.free.telesto.parser.utils.Nonce;
import sugar.free.telesto.parser.utils.crypto.Cryptograph;
import sugar.free.telesto.parser.utils.crypto.KeyPair;
import sugar.free.telesto.utils.DelayedActionThread;
import sugar.free.telesto.utils.NotificationUtil;
import sugar.free.telesto.utils.PairingDataStorage;

public class ConnectionService extends Service implements SocketHolder.Callback {

    private static final long RESPONSE_TIMEOUT = 6000;

    private List<StateCallback> stateCallbacks = Collections.synchronizedList(new ArrayList<>());
    private LocalBinder localBinder = new LocalBinder();
    private final Object $stateLock = new Object[0];
    private TelestoState state;
    protected PairingDataStorage pairingDataStorage;
    private PowerManager.WakeLock wakeLock;
    private final List<Object> connectionRequests = new ArrayList<>();
    private SocketHolder socketHolder;
    private DelayedActionThread disconnectionAwaiter;
    private DelayedActionThread recoveryAwaiter;
    DelayedActionThread timeoutThread;
    private BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    private BluetoothDevice bluetoothDevice;
    private BluetoothSocket bluetoothSocket;
    private boolean receiverRegistered;
    SatlMessage lastSatlMessage;
    KeyRequest keyRequest;
    private int socketAttempts = 0;
    private long waitingTime = 0;
    private ByteBuf byteBuf = new ByteBuf(1024);
    int recoveryAttempts = 0;
    String verificationString;
    SetupActivity setupActivity;
    final MessageQueue messageQueue = new MessageQueue();
    List<sugar.free.telesto.parser.app_layer.Service> activatedServices = Collections.synchronizedList(new ArrayList<>());

    private KeyPair keyPair;
    private byte[] randomBytes;

    KeyPair getKeyPair() {
        if  (keyPair == null) keyPair = Cryptograph.generateRSAKey();
        return keyPair;
    }

    byte[] getRandomBytes() {
        if (randomBytes == null) {
            randomBytes = new byte[28];
            new SecureRandom().nextBytes(randomBytes);
        }
        return randomBytes;
    }

    public void registerStateCallback(StateCallback stateCallback) {
        stateCallbacks.add(stateCallback);
    }

    public void unregisterStateCallback(StateCallback stateCallback) {
        stateCallbacks.remove(stateCallback);
    }

    public void setSetupActivity(SetupActivity setupActivity) {
        this.setupActivity = setupActivity;
    }

    public MessageRequest requestMessage(AppLayerMessage message) {
        MessageRequest messageRequest = new MessageRequest(message);
        if (getState() != TelestoState.CONNECTED) {
            messageRequest.exception = new DisconnectedException();
            return messageRequest;
        }
        synchronized (messageQueue) {
            if (message instanceof WriteConfigurationBlockMessage)
                messageQueue.enqueueRequest(new MessageRequest(new OpenConfigurationWriteSessionMessage()));
            messageQueue.enqueueRequest(messageRequest);
            if (message instanceof WriteConfigurationBlockMessage)
                messageQueue.enqueueRequest(new MessageRequest(new CloseConfigurationWriteSessionMessage()));
            requestNextMessage();
        }
        return messageRequest;
    }

    void requestNextMessage() {
        synchronized (messageQueue) {
            while (messageQueue.getActiveRequest() == null && messageQueue.hasPendingMessages()) {
                messageQueue.nextRequest();
                sugar.free.telesto.parser.app_layer.Service service = messageQueue.getActiveRequest().request.getService();
                if (service != sugar.free.telesto.parser.app_layer.Service.CONNECTION && !activatedServices.contains(service)) {
                    if (service.getServicePassword() == null) {
                        ActivateServiceMessage activateServiceMessage = new ActivateServiceMessage();
                        activateServiceMessage.setServiceID(ServiceIDs.IDS.getB(service));
                        activateServiceMessage.setVersion(service.getVersion());
                        activateServiceMessage.setServicePassword(new byte[16]);
                        sendAppLayerMessage(activateServiceMessage);
                    } else if (service.getServicePassword().length() != 16) {
                        messageQueue.completeActiveRequest(new InvalidServicePasswordException(0));
                    } else {
                        ServiceChallengeMessage serviceChallengeMessage = new ServiceChallengeMessage();
                        serviceChallengeMessage.setServiceID(ServiceIDs.IDS.getB(service));
                        serviceChallengeMessage.setVersion(service.getVersion());
                        sendAppLayerMessage(serviceChallengeMessage);
                    }
                } else sendAppLayerMessage(messageQueue.getActiveRequest().request);
            }
        }
    }

    @Override
    public void onCreate() {
        pairingDataStorage = new PairingDataStorage(this);
        state = pairingDataStorage.isPaired() ? TelestoState.DISCONNECTED : TelestoState.NOT_PAIRED;
        wakeLock = ((PowerManager) getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Telesto:ConnectionService");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    public TelestoState getState() {
        synchronized ($stateLock) {
            return state;
        }
    }

    void setState(TelestoState state) {
        synchronized ($stateLock) {
            if (this.state == state) return;
            this.state = state;
            if ((state == TelestoState.DISCONNECTED || state == TelestoState.NOT_PAIRED) && wakeLock.isHeld()) wakeLock.release();
            else if (!wakeLock.isHeld()) wakeLock.acquire();
            for (StateCallback stateCallback : stateCallbacks) stateCallback.stateChanged(state);
            Log.d("ConnectionService", "New state: " + state.name());
        }
    }

    public void requestConnection(Object lock) {
        synchronized (connectionRequests) {
            connectionRequests.add(lock);
            Log.d("ConnectionService", "Connection requested: " + lock);
            if (disconnectionAwaiter != null) disconnectionAwaiter.interrupt();
            TelestoState state = getState();
            switch (state) {
                case DISCONNECT_PENDING:
                    setState(TelestoState.CONNECTED);
                    break;
                case DISCONNECTED:
                    if (pairingDataStorage.isPaired()) initiateDisconnection();
                    break;
            }
        }
    }

    public void withdrawConnectionRequest(Object lock) {
        synchronized (connectionRequests) {
            connectionRequests.remove(lock);
            Log.d("ConnectionService", "Connection request withdrawn: " + lock);
            if (connectionRequests.size() == 0) {
                if (recoveryAwaiter != null) {
                    recoveryAwaiter.interrupt();
                    recoveryAwaiter = null;
                    setState(TelestoState.DISCONNECTED);
                } else if (getState() != TelestoState.NOT_PAIRED && getState() != TelestoState.APP_DISCONNECT_MESSAGE && getState() != TelestoState.DISCONNECTED) {
                    long disconnectionDelay = Math.max(1000, Math.min(30000, Long.parseLong(TelestoApp.getSharedPreferences().getString("disconnectionDelay", "10000"))));
                    Log.i("DisconnectionDelay", disconnectionDelay + "");
                    disconnectionAwaiter = DelayedActionThread.runDelayed(disconnectionDelay, this::disconnectionDelayExceeded);
                }
            }
        }
    }

    private void runRecoveryStrategies(boolean enforce) {
        if (TelestoApp.getSharedPreferences().getBoolean("waitBeforeRetry", true)) {
            long maxWaitingTime = Math.max(0, Math.min(60000, Long.parseLong(TelestoApp.getSharedPreferences().getString("maxWaitingTime", "20000"))));
            long minWaitingTime = Math.max(0, Math.min(30000, Long.parseLong(TelestoApp.getSharedPreferences().getString("minWaitingTime", "4000"))));
            if (enforce) waitingTime = maxWaitingTime;
            else if (waitingTime < minWaitingTime) waitingTime = minWaitingTime;
            else waitingTime += 1000;
            if (waitingTime > maxWaitingTime) waitingTime = maxWaitingTime;
        } else waitingTime = 0;
        socketAttempts++;
        if (TelestoApp.getSharedPreferences().getBoolean("allowSocketResets", true)
                && (socketAttempts > Math.max(0, Integer.parseInt(TelestoApp.getSharedPreferences().getString("maxSocketAttempts", "10"))) || enforce)) {
            Log.d("ConnectionService", "Exceeded maxSocketAttempts, discarding socket...");
            if (bluetoothSocket != null) {
                try {
                    bluetoothSocket.close();
                } catch (IOException e) {
                }
                bluetoothSocket = null;
            }
            socketAttempts = 0;
        }
    }

    private void initiateConnection() {
        if (waitingTime == 0) connect();
        else {
            setState(TelestoState.WAITING);
            recoveryAwaiter = DelayedActionThread.runDelayed(waitingTime, this::connect);
        }
    }

    private void initiateDisconnection() {
        if (getState() == TelestoState.CONNECTED) {
            synchronized (messageQueue) {
                if (messageQueue.getActiveRequest() == null) {
                    setState(TelestoState.APP_DISCONNECT_MESSAGE);
                    messageQueue.completePendingRequests(new AboutToDisconnectException());
                    sendAppLayerMessage(new DisconnectMessage());
                } else {
                    setState(TelestoState.DISCONNECT_PENDING);
                    messageQueue.completePendingRequests(new AboutToDisconnectException());
                }
            }
        } else disconnect();
    }

    private void connect() {
        recoveryAwaiter = null;
        if (bluetoothDevice == null) bluetoothDevice = bluetoothAdapter.getRemoteDevice(pairingDataStorage.getMacAddress());
        if (pairingDataStorage.isPaired() && bluetoothDevice.getBondState() != BluetoothDevice.BOND_BONDED) {
            handleConnectionRelatedException(new BluetoothBondRemovedException(), true);
            return;
        }
        setState(TelestoState.CONNECTING);
        socketHolder = new SocketHolder(this, bluetoothAdapter, !pairingDataStorage.isPaired(), bluetoothDevice, bluetoothSocket);
        socketHolder.connect();
    }

    private void cleanup() {
        if (socketHolder != null) {
            socketHolder.close();
            socketHolder = null;
        }
        if (disconnectionAwaiter != null) {
            disconnectionAwaiter.interrupt();
            disconnectionAwaiter = null;
        }
        if (recoveryAwaiter != null) {
            recoveryAwaiter.interrupt();
            recoveryAwaiter = null;
        }
        if (timeoutThread != null) {
            timeoutThread.interrupt();
            timeoutThread = null;
        }
        if (receiverRegistered) {
            unregisterReceiver(broadcastReceiver);
            receiverRegistered = false;
        }
        lastSatlMessage = null;
        keyRequest = null;
        byteBuf = new ByteBuf(1024);
        verificationString = null;
        messageQueue.reset();
        activatedServices.clear();
    }

    public void reset() {
        Log.d("ConnectionService", "Reset");
        cleanup();
        socketAttempts = 0;
        waitingTime = 0;
        recoveryAttempts = 0;
        bluetoothSocket = null;
        bluetoothDevice = null;
        setState(TelestoState.NOT_PAIRED);
        pairingDataStorage.reset();
    }

    void disconnect() {
        Log.d("ConnectionService", "Disconnect");
        cleanup();
        if (connectionRequests.size() > 0) initiateConnection();
        else setState(TelestoState.DISCONNECTED);
    }

    public synchronized void pair(String macAddress) {
        Log.d("ConnectionService", "Pairing with " + macAddress);
        pairingDataStorage.setMacAddress(macAddress);
        connect();
    }

    public synchronized void confirmVerificationString() {
        Log.d("ConnectionService", "Verification string confirmed");
        VerifyConfirmRequest verifyConfirmRequest = new VerifyConfirmRequest();
        verifyConfirmRequest.setPairingStatus(PairingStatus.CONFIRMED);
        setState(TelestoState.SATL_VERIFY_CONFIRM_REQUEST);
        sendSatlMessage(verifyConfirmRequest, true);
    }

    public synchronized void rejectVerificationString() {
        Log.d("ConnectionService", "Verification string rejected");
        VerifyConfirmRequest verifyConfirmRequest = new VerifyConfirmRequest();
        verifyConfirmRequest.setPairingStatus(PairingStatus.REJECTED);
        sendSatlMessage(verifyConfirmRequest, true);
        handleConnectionRelatedException(new SatlPairingRejectedException(), true);
    }

    private void disconnectionDelayExceeded() {
        Log.d("ConnectionService", "Disconnection delay exceeded");
        disconnectionAwaiter = null;
        initiateDisconnection();
    }

    void handleConnectionRelatedException(Exception exception, boolean critical) {
        if (critical) Log.d("ConnectionService", "Critical exception occurred: " + exception.getClass().getCanonicalName());
        else Log.d("ConnectionService", "Exception occurred: " + exception.getClass().getCanonicalName());
        cleanup();
        if (!pairingDataStorage.isPaired()) {
            if (setupActivity != null) setupActivity.displayException(exception);
            reset();
        } else if (critical) {
            reset();
            NotificationUtil.showCriticalErrorNotification(this);
            Intent intent = new Intent(this, LauncherActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
        } else if (connectionRequests.size() > 0) initiateConnection();
    }

    @Override
    public void onSocketCreated(BluetoothSocket bluetoothSocket) {
        this.bluetoothSocket = bluetoothSocket;
    }

    @Override
    public void onSocketCreationFailed() {
        handleConnectionRelatedException(new SocketCreationFailedException(), false);
    }

    @Override
    public void onConnectionSucceeded() {
        Log.d("ConnectionService", "Connection succeeded");
        waitingTime = 0;
        socketAttempts = 0;
        if (!receiverRegistered) {
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECT_REQUESTED);
            intentFilter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED);
            registerReceiver(broadcastReceiver, intentFilter);
            receiverRegistered = true;
        }
        if (pairingDataStorage.isPaired()) {
            setState(TelestoState.SATL_SYN_REQUEST);
            sendSatlMessage(new SynRequest(), true);
        } else {
            setState(TelestoState.SATL_CONNECTION_REQUEST);
            sendSatlMessage(new ConnectionRequest(), true);
        }
    }

    @Override
    public void onConnectionFailed(long durationOfAttempt) {
        Log.d("ConnectionService", "Connection failed");
        runRecoveryStrategies(durationOfAttempt < 1000);
        handleConnectionRelatedException(new ConnectionFailedException(), false);
    }

    @Override
    public void onConnectionLost() {
        Log.d("ConnectionService", "Connection lost");
        if (receiverRegistered) {
            unregisterReceiver(broadcastReceiver);
            receiverRegistered = false;
        }
        handleConnectionRelatedException(new ConnectionLostException(), false);
    }

    @Override
    public void onBytesReceived(byte[] bytes, int length) {
        byteBuf.putBytes(bytes, length);
        while (SatlMessage.hasCompletePacket(byteBuf)) {
            try {
                SatlMessage satlMessage = SatlMessage.deserialize(byteBuf, pairingDataStorage.getLastNonceReceived(), pairingDataStorage.getIncomingKey());
                SatlMessageHandler.processSatlMessage(this, satlMessage);
            } catch (OrbitalException e) {
                handleConnectionRelatedException(e, false);
            }
        }
    }

    void sendSatlMessage(SatlMessage satlMessage, boolean prepare) {
        if (socketHolder == null) return;
        this.lastSatlMessage = satlMessage;
        if (prepare) {
            satlMessage.setCommID(pairingDataStorage.getCommId());
            Nonce nonce = pairingDataStorage.getLastNonceSent();
            if (nonce != null) {
                nonce.increment();
                pairingDataStorage.setLastNonceSent(nonce);
            }
            satlMessage.setNonce(nonce);
        }
        ByteBuf serialized = satlMessage.serialize(satlMessage.getClass(), pairingDataStorage.getOutgoingKey());
        if (timeoutThread != null) timeoutThread.interrupt();
        timeoutThread = DelayedActionThread.runDelayed(RESPONSE_TIMEOUT, () -> handleConnectionRelatedException(new TimeoutException(), false));
        socketHolder.sendBytes(serialized.getBytes());
    }

    void sendAppLayerMessage(AppLayerMessage appLayerMessage) {
        sendSatlMessage(AppLayerMessage.wrap(appLayerMessage), true);
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return localBinder;
    }

    private BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (pairingDataStorage.getMacAddress() != null && pairingDataStorage.getMacAddress()
                    .equals(((BluetoothDevice) intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)).getAddress())) {
                handleConnectionRelatedException(new ConnectionLostException(), false);
                Log.d("ConnectionService", "ACL Disconnect");
            }
        }
    };

    public class LocalBinder extends Binder {
        public ConnectionService getService() {
            return ConnectionService.this;
        }
    }

    public interface StateCallback {
        void stateChanged(TelestoState state);
    }
}
