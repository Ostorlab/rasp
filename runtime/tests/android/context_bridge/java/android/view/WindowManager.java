package android.view;
public class WindowManager {
    public static class LayoutParams {}
    public static final int SCREEN_RECORDING_STATE_NOT_VISIBLE = 0;
    public static final int SCREEN_RECORDING_STATE_VISIBLE = 1;
    public static final java.util.List<java.util.function.Consumer<Integer>> callbacks = new java.util.ArrayList<>();
    public static int initial;
    public static Integer duringRegistration;
    public boolean failRegistration;
    public boolean failRemoval;
    public int addScreenRecordingCallback(java.util.concurrent.Executor executor, java.util.function.Consumer<Integer> callback) {
        callbacks.add(callback);
        if (duringRegistration != null) executor.execute(() -> callback.accept(duringRegistration));
        if (failRegistration) throw new IllegalStateException("recording registration after side effects");
        return initial;
    }
    public void removeScreenRecordingCallback(java.util.function.Consumer<Integer> callback) {
        if (failRemoval) throw new IllegalStateException("recording unregister");
        callbacks.remove(callback);
    }
    public static void recording(Integer state) {
        for (java.util.function.Consumer<Integer> callback : new java.util.ArrayList<>(callbacks)) callback.accept(state);
    }
}
