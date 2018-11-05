package sugar.free.telesto.services.connection_service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import sugar.free.telesto.parser.app_layer.AppLayerMessage;

public class MessageQueue {

    MessageRequest activeRequest;
    final List<MessageRequest> messageRequests = new ArrayList<>();

    public synchronized MessageRequest getActiveRequest() {
        return activeRequest;
    }

    public synchronized void completeActiveRequest(AppLayerMessage response) {
        if (activeRequest == null) return;
        synchronized (activeRequest) {
            activeRequest.response = response;
            activeRequest.notifyAll();
        }
        activeRequest = null;
    }

    public synchronized void completeActiveRequest(Exception exception) {
        if (activeRequest == null) return;
        synchronized (activeRequest) {
            activeRequest.exception = exception;
            activeRequest.notifyAll();
        }
        activeRequest = null;
    }

    public synchronized void completePendingRequests(Exception exception) {
        for (MessageRequest messageRequest : messageRequests) {
            synchronized (messageRequest) {
                messageRequest.exception = exception;
                messageRequest.notifyAll();
            }
        }
    }

    public synchronized void enqueueRequest(MessageRequest messageRequest) {
        messageRequests.add(messageRequest);
        Collections.sort(messageRequests);
    }

    public synchronized void nextRequest() {
        if (messageRequests.size() != 0) {
            activeRequest = messageRequests.get(0);
            messageRequests.remove(0);
        }
    }

    public synchronized boolean hasPendingMessages() {
        return messageRequests.size() != 0;
    }

    public synchronized void reset() {
        activeRequest = null;
        messageRequests.clear();
    }
}
