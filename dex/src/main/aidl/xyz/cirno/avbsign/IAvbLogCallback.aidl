package xyz.cirno.avbsign;

oneway interface IAvbLogCallback {
    void onLog(long sequence, int level, String msg);
}
