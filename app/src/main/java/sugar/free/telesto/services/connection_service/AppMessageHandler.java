package sugar.free.telesto.services.connection_service;

import android.util.Log;

import org.spongycastle.crypto.InvalidCipherTextException;

import sugar.free.telesto.descriptors.TelestoState;
import sugar.free.telesto.exceptions.AboutToDisconnectException;
import sugar.free.telesto.exceptions.ReceivedPacketInInvalidStateException;
import sugar.free.telesto.exceptions.SatlPairingRejectedException;
import sugar.free.telesto.parser.app_layer.AppLayerMessage;
import sugar.free.telesto.parser.app_layer.connection.ActivateServiceMessage;
import sugar.free.telesto.parser.app_layer.connection.BindMessage;
import sugar.free.telesto.parser.app_layer.connection.ConnectMessage;
import sugar.free.telesto.parser.app_layer.connection.DisconnectMessage;
import sugar.free.telesto.parser.app_layer.connection.ServiceChallengeMessage;
import sugar.free.telesto.parser.ids.ServiceIDs;
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

public final class AppMessageHandler {

    private AppMessageHandler() {
    }

    static void processDataMessage(ConnectionService connectionService, DataMessage dataMessage) {
        TelestoState state = connectionService.getState();
        switch (state) {
            case CONNECTED:
            case APP_BIND_MESSAGE:
            case APP_CONNECT_MESSAGE:
            case DISCONNECT_PENDING:
            case APP_DISCONNECT_MESSAGE:
                break;
            default:
                connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), false);
                return;
        }
        try {
            AppLayerMessage appLayerMessage = AppLayerMessage.unwrap(dataMessage);
            Log.d("ConnectionService", "Received AppLayerMessage: " + appLayerMessage.getClass().getSimpleName());
            if (appLayerMessage instanceof BindMessage) processBindMessage(connectionService);
            else if (appLayerMessage instanceof ConnectMessage) processConnectMessage(connectionService);
            else if (appLayerMessage instanceof ActivateServiceMessage) processActivateServiceMessage(connectionService);
            else if (appLayerMessage instanceof ServiceChallengeMessage) processServiceChallengeMessage(connectionService, (ServiceChallengeMessage) appLayerMessage);
            else if (appLayerMessage instanceof DisconnectMessage) processDisconnectMessage(connectionService);
            else if (!(appLayerMessage instanceof sugar.free.telesto.parser.app_layer.connection.DisconnectMessage)) processGenericAppLayerMessage(connectionService, appLayerMessage);
        } catch (Exception e) {
            if (state != TelestoState.CONNECTED) connectionService.handleConnectionRelatedException(e, true);
            else {
                Log.d("ConnectionService", "Got exception while processing request: " + e.getClass().getCanonicalName());
                synchronized (connectionService.messageQueue) {
                    if (connectionService.getState() == TelestoState.DISCONNECT_PENDING) {
                        connectionService.setState(TelestoState.APP_DISCONNECT_MESSAGE);
                        connectionService.messageQueue.completeActiveRequest(e);
                        connectionService.sendAppLayerMessage(new DisconnectMessage());
                    } else connectionService.messageQueue.completeActiveRequest(e);
                }
            }
        }
    }

    private static void processBindMessage(ConnectionService connectionService) {
        if (connectionService.getState() != TelestoState.APP_BIND_MESSAGE) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), true);
            return;
        }
        connectionService.pairingDataStorage.setPaired(true);
        connectionService.setState(TelestoState.CONNECTED);
    }

    private static void processConnectMessage(ConnectionService connectionService) {
        if (connectionService.getState() != TelestoState.APP_CONNECT_MESSAGE) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), false);
            return;
        }
        connectionService.setState(TelestoState.CONNECTED);
    }

    private static void processDisconnectMessage(ConnectionService connectionService) {
        if (connectionService.getState() != TelestoState.APP_DISCONNECT_MESSAGE) {
            connectionService.handleConnectionRelatedException(new ReceivedPacketInInvalidStateException(), false);
            return;
        }
        connectionService.activatedServices.clear();
        connectionService.disconnect();
    }

    private static void processActivateServiceMessage(ConnectionService connectionService) {
        synchronized (connectionService.messageQueue) {
            connectionService.activatedServices.add(connectionService.messageQueue.getActiveRequest().request.getService());
            if (connectionService.getState() == TelestoState.DISCONNECT_PENDING) {
                connectionService.setState(TelestoState.APP_DISCONNECT_MESSAGE);
                connectionService.sendAppLayerMessage(new DisconnectMessage());
            } else connectionService.sendAppLayerMessage(connectionService.messageQueue.getActiveRequest().request);
        }
    }

    private static void processServiceChallengeMessage(ConnectionService connectionService, ServiceChallengeMessage serviceChallengeMessage) {
        synchronized (connectionService.messageQueue) {
            if (connectionService.getState() == TelestoState.DISCONNECT_PENDING) {
                connectionService.setState(TelestoState.APP_DISCONNECT_MESSAGE);
                connectionService.messageQueue.completeActiveRequest(new AboutToDisconnectException());
                connectionService.sendAppLayerMessage(new DisconnectMessage());
            } else {
                sugar.free.telesto.parser.app_layer.Service service = connectionService.messageQueue.getActiveRequest().request.getService();
                ActivateServiceMessage activateServiceMessage = new ActivateServiceMessage();
                activateServiceMessage.setServiceID(ServiceIDs.IDS.getB(service));
                activateServiceMessage.setVersion(service.getVersion());
                activateServiceMessage.setServicePassword(Cryptograph.getServicePasswordHash(service.getServicePassword(), serviceChallengeMessage.getRandomData()));
                connectionService.sendAppLayerMessage(activateServiceMessage);
            }
        }
    }

    private static void processGenericAppLayerMessage(ConnectionService connectionService, AppLayerMessage appLayerMessage) {
        synchronized (connectionService.messageQueue) {
            if (connectionService.getState() == TelestoState.DISCONNECT_PENDING) {
                final MessageRequest messageRequest = connectionService.messageQueue.getActiveRequest();
                synchronized (connectionService.messageQueue.getActiveRequest()) {
                    messageRequest.response = appLayerMessage;
                    messageRequest.notifyAll();
                }
                connectionService.setState(TelestoState.APP_DISCONNECT_MESSAGE);
                connectionService.sendAppLayerMessage(new DisconnectMessage());
            } else {
                connectionService.messageQueue.completeActiveRequest(appLayerMessage);
                connectionService.requestNextMessage();
            }
        }
    }
}
