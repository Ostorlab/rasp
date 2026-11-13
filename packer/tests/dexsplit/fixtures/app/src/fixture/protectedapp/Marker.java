package fixture.protectedapp;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
@Retention(RetentionPolicy.RUNTIME)
public @interface Marker { String value(); int[] numbers() default {1, 2, 3}; }
