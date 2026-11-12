package android.view;
import android.view.accessibility.AccessibilityEvent;
import java.util.List;
public class Window {
 private Callback callback;
 public final Callback getCallback() { return callback; }
 public void setCallback(Callback callback) { this.callback = callback; }
 public interface Callback {
 boolean dispatchTouchEvent(MotionEvent motion);
 void onDetachedFromWindow();
 boolean dispatchKeyEvent(KeyEvent event);
 boolean dispatchKeyShortcutEvent(KeyEvent event);
 boolean dispatchTrackballEvent(MotionEvent event);
 boolean dispatchGenericMotionEvent(MotionEvent event);
 boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent event);
 View onCreatePanelView(int feature);
 boolean onCreatePanelMenu(int feature, Menu menu);
 boolean onPreparePanel(int feature, View view, Menu menu);
 boolean onMenuOpened(int feature, Menu menu);
 boolean onMenuItemSelected(int feature, MenuItem item);
 void onWindowAttributesChanged(WindowManager.LayoutParams attrs);
 void onContentChanged();
 void onWindowFocusChanged(boolean focused);
 void onAttachedToWindow();
 void onPanelClosed(int feature, Menu menu);
 boolean onSearchRequested();
 boolean onSearchRequested(SearchEvent event);
 ActionMode onWindowStartingActionMode(ActionMode.Callback callback);
 ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int type);
 void onActionModeStarted(ActionMode mode);
 void onActionModeFinished(ActionMode mode);
 void onProvideKeyboardShortcuts(List<KeyboardShortcutGroup> data, Menu menu, int device);
 void onPointerCaptureChanged(boolean captured);
 }
}
