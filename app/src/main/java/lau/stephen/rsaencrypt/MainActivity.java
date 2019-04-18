package lau.stephen.rsaencrypt;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    boolean isEncoded = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        final TextView tv = findViewById(R.id.sample_text);

        tv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (isEncoded) {
                    String encodedString = EncryptUtils.encode(tv.getText().toString());
                    tv.setText(encodedString);
                } else {
                    String decodedString = EncryptUtils.decode(tv.getText().toString());
                    tv.setText(decodedString);
                }
                isEncoded = !isEncoded;
            }
        });

    }

}
