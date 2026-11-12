package fixture.protectedapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** Harmless ART acceptance fixture: fixed arithmetic, package access, interface dispatch and exceptions. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        int actual = Business.answer(0);
        String result = actual == 42 ? "PK02_RESULT=42 PACKAGE_PRIVATE_OK" : "PK02_FAILURE=" + actual;
        Log.i("PK02", result);
        TextView view = new TextView(this);
        view.setText(result);
        setContentView(view);
    }
}
