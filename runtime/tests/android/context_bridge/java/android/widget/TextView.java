package android.widget;
/** Status output only, deliberately no getText/editor API. */
public class TextView extends android.view.View {
    public String output = "";
    public TextView(Object context) {}
    public void setText(CharSequence value) { output = value.toString(); }
}
