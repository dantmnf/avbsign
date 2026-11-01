package xyz.cirno.avbsign;

oneway interface IAvbLogCallback {
    void onLog(int level, String msg);
}
