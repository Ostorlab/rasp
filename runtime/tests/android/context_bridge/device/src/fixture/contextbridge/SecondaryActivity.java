package fixture.contextbridge;

/** Neutral second Activity for real multi-window capture lifecycle checks. */
public final class SecondaryActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        android.widget.TextView view = new android.widget.TextView(this);
        view.setText("Second observation Activity. Use only neutral screenshot/recording test content.");
        setContentView(view);
    }
}
