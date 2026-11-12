package fixture.protectedapp;
import fixture.library.Library;
import fixture.external.Extra;

@Marker(value = "retained annotation", numbers = {3, 5})
public final class Business implements Worker {
    public static final String TEXT = "retained string";
    public static final long WIDE = 0x123456789abcdefL;
    public static int answer(int input) {
        int selected;
        switch (input) { case 0: selected = 7; break; case 8: selected = 9; break; default: selected = 11; }
        try {
            if (input == 0) throw new IllegalArgumentException("fixture");
            selected = 0;
        } catch (IllegalArgumentException expected) {
            selected += Helper.packagePrivateValue();
        }
        int[] values = {selected, Library.zero(), Extra.zero()};
        return values[0] + values[1] + values[2] + new Business().adjustment();
    }
}
