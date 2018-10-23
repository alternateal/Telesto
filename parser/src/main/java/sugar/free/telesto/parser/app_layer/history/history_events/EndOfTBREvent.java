package sugar.free.telesto.parser.app_layer.history.history_events;

import sugar.free.telesto.parser.utils.BOCUtil;
import sugar.free.telesto.parser.utils.ByteBuf;

public class EndOfTBREvent extends HistoryEvent {

    private int startHour;
    private int startMinute;
    private int startSecond;
    private int amount;
    private int duration;

    @Override
    public void parse(ByteBuf byteBuf) {
        byteBuf.shift(1);
        startHour = BOCUtil.parseBOC(byteBuf.readByte());
        startMinute = BOCUtil.parseBOC(byteBuf.readByte());
        startSecond = BOCUtil.parseBOC(byteBuf.readByte());
        amount = byteBuf.readUInt16LE();
        duration = byteBuf.readUInt16LE();
    }

    public int getStartHour() {
        return startHour;
    }

    public int getStartMinute() {
        return startMinute;
    }

    public int getStartSecond() {
        return startSecond;
    }

    public int getAmount() {
        return amount;
    }

    public int getDuration() {
        return duration;
    }
}
