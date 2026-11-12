package android.view;
/** UI callback boundary only; no input contents exist. */
public class View {
    public interface OnClickListener { void onClick(View view); }
    public OnClickListener listener;
    public void setOnClickListener(OnClickListener value) { listener = value; }
    public boolean performClick() {
        if (listener == null) return false;
        listener.onClick(this); return true;
    }
}
