package android.widget;
import android.text.method.TransformationMethod;
/** No getText/key/selection API, so a content-reading sampler cannot compile against this fixture. */
public class EditText extends android.view.View {
    public EditText() {}
    public EditText(Object context) {}
    public int inputType;
    public TransformationMethod transformation;
    public int getInputType() { return inputType; }
    public TransformationMethod getTransformationMethod() { return transformation; }
    public void setInputType(int value) { inputType = value; }
    public void setTransformationMethod(TransformationMethod value) { transformation = value; }
    public void setHint(String value) {}
}
