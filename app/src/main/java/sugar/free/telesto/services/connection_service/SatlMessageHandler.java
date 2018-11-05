package sugar.free.telesto.services.connection_service;

import org.spongycastle.crypto.InvalidCipherTextException;

import sugar.free.telesto.descriptors.TelestoState;
import sugar.free.telesto.exceptions.ReceivedPacketInInvalidStateException;
import sugar.free.telesto.exceptions.RecoveryFailedException;
import sugar.free.telesto.exceptions.SatlPairingRejectedException;
import sugar.free.telesto.exceptions.satl_errors.SatlWrongStateException;
import sugar.free.telesto.exceptions.satl_errors.SatlCompatibleStateErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlIncompatibleVersionErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlInvalidCommIdErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlInvalidMessageTypeErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlInvalidPacketErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlInvalidPayloadLengthErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlNoneErrorException;
import sugar.free.telesto.exceptions.satl_errors.SatlUndefinedErrorException;
import sugar.free.telesto.parser.app_layer.connection.BindMessage;
import sugar.free.telesto.parser.app_layer.connection.ConnectMessage;
import sugar.free.telesto.parser.satl.ConnectionResponse;
import sugar.free.telesto.parser.satl.DataMessage;
import sugar.free.telesto.parser.satl.ErrorMessage;
import sugar.free.telesto.parser.satl.KeyRequest;
import sugar.free.telesto.parser.satl.KeyResponse;
import sugar.free.telesto.parser.satl.PairingStatus;
import sugar.free.telesto.parser.satl.SatlMessage;
import sugar.free.telesto.parser.satl.SynAckResponse;
import sugar.free.telesto.parser.satl.VerifyConfirmRequest;
import sugar.free.telesto.parser.satl.VerifyConfirmResponse;
import sugar.free.telesto.parser.satl.VerifyDisplayRequest;
import sugar.free.telesto.parser.satl.VerifyDisplayResponse;
import sugar.free.telesto.parser.utils.Nonce;
import sugar.free.telesto.parser.utils.crypto.Cryptograph;
import sugar.free.telesto.parser.utils.crypto.DerivedKeys;

public final class SatlMessageHandler {

    private static final int NONCE_RECOVERY_INCREASE = 50;

    private SatlMessageHandler() {
    }

    static void processSatlMessage(ConnectionService connectionService, SatlMessage satlMessage) {
        if (connectionService.timeoutThread != null) {
            connectionService.timeoutThread.interrupt();
            connectionService.timeoutThread = null;
        }
        connectionService.recoveryAttempts = 0;
        connectionService.pairingDataStorage.setLastNonceReceived(satlMessage.getNonce());
        if (!(satlMessage instanceof ErrorMessage)) connectionService.recoveryAttempts = 0;
        if (satlMessage instanceof ConnectionResponse) processConnectionResponse(connectionService);
        else if (satlMessage instanceof KeyResponse) processKeyResponse(connectionService, (KeyResponse) satlMessage);
        else if (satlMessage instanceof VerifyDisplayResponse) processVerifyDisplayResponse(connectionService);
        else if (satlMessage instanceof VerifyConfirmResponse)
            processVerifyConfirmResponse(connectionService, (VerifyConfirmResponse) satlMessage);
        else if (satlMessage instanceof DataMessage) AppMessageHandler.processDataMessage(connectionService, (DataMessage) satlMessage);
        else if (satlMessage instanceof SynAckResponse) processSynAckResponse(connectionService);
        else if (satlMessage instanceof ErrorMessage)
            processErrorMessage(connectionService, (ErrorMessage) satlMessage);
    }

    private static void processConnectionResponse(ConnectionService connectionService) {
        if (connectionService.getState() != TelestoState.SATL_CONNECTION_REQUEST) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), true);
            return;
        }
        connectionService.keyRequest = new KeyRequest();
        connectionService.keyRequest.setPreMasterKey(connectionService.getKeyPair().getPublicKeyBytes());
        connectionService.keyRequest.setRandomBytes(connectionService.getRandomBytes());
        connectionService.setState(TelestoState.SATL_KEY_REQUEST);
        connectionService.sendSatlMessage(connectionService.keyRequest, true);
    }

    private static void processKeyResponse(ConnectionService connectionService, KeyResponse keyResponse) {
        if (connectionService.getState() != TelestoState.SATL_KEY_REQUEST) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), true);
            return;
        }
        try {
            DerivedKeys derivedKeys = Cryptograph.deriveKeys(Cryptograph.combine(connectionService.keyRequest.getSatlContent(), keyResponse.getSatlContent()),
                    Cryptograph.decryptRSA(connectionService.getKeyPair().getPrivateKey(), keyResponse.getPreMasterSecret()),
                    connectionService.getRandomBytes(),
                    keyResponse.getRandomData());
            connectionService.pairingDataStorage.setCommId(keyResponse.getCommID());
            connectionService.keyRequest = null;
            connectionService.verificationString = derivedKeys.getVerificationString();
            connectionService.pairingDataStorage.setOutgoingKey(derivedKeys.getOutgoingKey());
            connectionService.pairingDataStorage.setIncomingKey(derivedKeys.getIncomingKey());
            connectionService.pairingDataStorage.setLastNonceSent(new Nonce());
            connectionService.setState(TelestoState.SATL_VERIFY_DISPLAY_REQUEST);
            connectionService.sendSatlMessage(new VerifyDisplayRequest(), true);
        } catch (InvalidCipherTextException e) {
            connectionService.handleConnectionRelatedException(e, true);
        }
    }

    private static void processVerifyDisplayResponse(ConnectionService connectionService) {
        if (connectionService.getState() != TelestoState.SATL_VERIFY_DISPLAY_REQUEST) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), true);
            return;
        }
        connectionService.setState(TelestoState.AWAITING_CODE_CONFIRMATION);
        if (connectionService.setupActivity != null) connectionService.setupActivity.showVerificationString(connectionService.verificationString);
        connectionService.verificationString = null;
    }

    private static void processVerifyConfirmResponse(ConnectionService connectionService, VerifyConfirmResponse verifyConfirmResponse) {
        if (connectionService.getState() != TelestoState.SATL_VERIFY_CONFIRM_REQUEST) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), true);
            return;
        }
        switch (verifyConfirmResponse.getPairingStatus()) {
            case CONFIRMED:
                connectionService.setState(TelestoState.APP_BIND_MESSAGE);
                connectionService.sendAppLayerMessage(new BindMessage());
                break;
            case PENDING:
                try {
                    Thread.sleep(200);
                    VerifyConfirmRequest verifyConfirmRequest = new VerifyConfirmRequest();
                    verifyConfirmRequest.setPairingStatus(PairingStatus.CONFIRMED);
                    connectionService.sendSatlMessage(verifyConfirmRequest, true);
                } catch (InterruptedException e) {
                    //Redirect interrupt flag
                    Thread.currentThread().interrupt();
                }
                break;
            case REJECTED:
                connectionService.handleConnectionRelatedException(new SatlPairingRejectedException(), true);
                break;
        }
    }

    private static void processSynAckResponse(ConnectionService connectionService) {
        if (connectionService.getState() != TelestoState.SATL_SYN_REQUEST) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), true);
            return;
        }
        connectionService.setState(TelestoState.APP_CONNECT_MESSAGE);
        connectionService.sendAppLayerMessage(new ConnectMessage());
    }

    private static void processErrorMessage(ConnectionService connectionService, ErrorMessage errorMessage) {
        switch (errorMessage.getError()) {
            case INVALID_NONCE:
                if (connectionService.getState() == TelestoState.SATL_SYN_REQUEST) {
                    Nonce nonce = connectionService.pairingDataStorage.getLastNonceSent();
                    nonce.increment(NONCE_RECOVERY_INCREASE - 1);
                    connectionService.pairingDataStorage.setLastNonceSent(nonce);
                    connectionService.lastSatlMessage.setNonce(nonce);
                } else {
                    connectionService.handleConnectionRelatedException(new RecoveryFailedException(), true);
                    break;
                }
            case INVALID_CRC:
            case INVALID_MAC_TRAILER:
            case DECRYPT_VERIFY_FAILED:
                connectionService.recoveryAttempts++;
                if (connectionService.recoveryAttempts <= 10) connectionService.sendSatlMessage(connectionService.lastSatlMessage, false);
                else connectionService.handleConnectionRelatedException(new RecoveryFailedException(), true);
                break;
            case INVALID_PAYLOAD_LENGTH:
                connectionService.handleConnectionRelatedException(new SatlInvalidPayloadLengthErrorException(), false);
                break;
            case INVALID_MESSAGE_TYPE:
                connectionService.handleConnectionRelatedException(new SatlInvalidMessageTypeErrorException(), false);
                break;
            case INCOMPATIBLE_VERSION:
                connectionService.handleConnectionRelatedException(new SatlIncompatibleVersionErrorException(), true);
                break;
            case COMPATIBLE_STATE:
                connectionService.handleConnectionRelatedException(new SatlCompatibleStateErrorException(), true);
                break;
            case INVALID_COMM_ID:
                connectionService.handleConnectionRelatedException(new SatlInvalidCommIdErrorException(), true);
                break;
            case INVALID_PACKET:
                connectionService.handleConnectionRelatedException(new SatlInvalidPacketErrorException(), false);
                break;
            case WRONG_STATE:
                connectionService.handleConnectionRelatedException(new SatlWrongStateException(), true);
                break;
            case UNDEFINED:
                connectionService.handleConnectionRelatedException(new SatlUndefinedErrorException(), true);
                break;
            case NONE:
                connectionService.handleConnectionRelatedException(new SatlNoneErrorException(), true);
                break;
        }
    }

}
