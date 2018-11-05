package sugar.free.telesto.services.connection_service;

import sugar.free.telesto.parser.app_layer.AppLayerMessage;

public class MessageRequest implements Comparable<MessageRequest> {

    AppLayerMessage request;
    AppLayerMessage response;
    Exception exception;

    MessageRequest(AppLayerMessage request) {
        this.request = request;
    }

    public AppLayerMessage await() throws Exception {
        synchronized (this) {
            while (exception == null && response == null) wait();
            if (exception != null) throw exception;
            return response;
        }
    }

    @Override
    public int compareTo(MessageRequest messageRequest) {
        return request.compareTo(messageRequest.request);
    }

    public AppLayerMessage getRequest() {
        return this.request;
    }

    public AppLayerMessage getResponse() {
        return this.response;
    }

    public Exception getException() {
        return this.exception;
    }
}
