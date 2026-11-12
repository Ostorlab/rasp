package android.widget;
import android.text.method.TransformationMethod;
/** No getText/key/selection API, so a content-reading sampler cannot compile against this fixture. */
public class EditText {
    public int inputType;
    public TransformationMethod transformation;
    public int getInputType() { return inputType; }
    public TransformationMethod getTransformationMethod() { return transformation; }
}
