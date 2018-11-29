package org.bjoern.jbranca;

class Time {

    private Time() {
    }

    static int unixTimeNow() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private static byte[] bigEndian(int unixTime) {
        return new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime
        };
    }

    static byte[] makeTimestamp() {
        return bigEndian(unixTimeNow());
    }
}
