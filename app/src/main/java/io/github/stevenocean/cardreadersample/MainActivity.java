package io.github.stevenocean.cardreadersample;

import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.MifareUltralight;
import android.os.Parcelable;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    private NfcAdapter mNfcAdapter;
    private TextView mNfcInfoText;
    private static final String TAG = MainActivity.class.getName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mNfcInfoText = findViewById(R.id.nfc_info_tv);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (null == mNfcAdapter) {
            mNfcInfoText.setText("Not support NFC!");
            finish();
            return;
        }

        if (!mNfcAdapter.isEnabled()) {
            mNfcInfoText.setText("Please open NFC!");
            finish();
            return;
        }

        if (getIntent() != null) {
            processIntent(getIntent());
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent != null) {
            processIntent(intent);
        }
    }

    private void processIntent(Intent intent) {

        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Toast.makeText(this, "ACTION_TECH_DISCOVERED", Toast.LENGTH_LONG).show();
        } else if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intent.getAction())) {
            Toast.makeText(this, "ACTION_TAG_DISCOVERED", Toast.LENGTH_LONG).show();
        } else {
            Toast.makeText(this, "Invalid action", Toast.LENGTH_LONG).show();
            return;
        }

        StringBuilder nfcInfo = new StringBuilder();
        byte[] extraId = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);

        // Id
        if (extraId != null) {
            nfcInfo.append("ID (hex): ").append(encodeHexString(extraId)).append("\n");
        }

        // Tag info
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        // Technologies
        StringBuilder technologiesAvailable = new StringBuilder("Technologies Available: \n");

        // Card type.
        StringBuilder cardType = new StringBuilder("Card Type: \n");

        // Sector and block.
        StringBuilder sectorAndBlock = new StringBuilder("Storage: \n");

        // Sector check
        StringBuilder sectorCheck = new StringBuilder("Sector check: \n");

        // Card response for IsoDep
        StringBuilder cardResp = new StringBuilder("Card response: \n");

        int idx = 0;
        for (String tech : tag.getTechList()) {
            if (tech.equals(MifareClassic.class.getName())) {
                // Mifare Classic
                MifareClassic mfc = MifareClassic.get(tag);
                switch (mfc.getType()) {
                    case MifareClassic.TYPE_CLASSIC:
                        cardType.append("Classic");
                        break;

                    case MifareClassic.TYPE_PLUS:
                        cardType.append("Plus");
                        break;

                    case MifareClassic.TYPE_PRO:
                        cardType.append("Pro");
                        break;

                    case MifareClassic.TYPE_UNKNOWN:
                        cardType.append("Unknown");
                        break;
                }

                sectorAndBlock.append("Sectors: ").append(mfc.getSectorCount()).append("\n")
                        .append("Blocks: ").append(mfc.getBlockCount()).append("\n")
                        .append("Size: ").append(mfc.getSize()).append(" Bytes");

                try {
                    // Enable I/O to the tag
                    mfc.connect();

                    for (int i = 0; i < mfc.getSectorCount(); ++i) {
                        if (mfc.authenticateSectorWithKeyA(i, MifareClassic.KEY_DEFAULT)) {
                            sectorCheck.append("Sector <").append(i).append("> with KeyA auth succ\n");

                            // Read block of sector
                            final int blockIndex = mfc.sectorToBlock(i);
                            for (int j = 0; j < mfc.getBlockCountInSector(i); ++j) {
                                byte[] blockData = mfc.readBlock(blockIndex+j);
                                sectorCheck.append("  Block <").append(blockIndex+j).append("> ")
                                        .append(encodeHexString(blockData)).append("\n");
                            }

                        } else if (mfc.authenticateSectorWithKeyB(i, MifareClassic.KEY_DEFAULT)) {
                            sectorCheck.append("Sector <").append(i).append("> with KeyB auth succ\n");

                            // Read block of sector
                            final int blockIndex = mfc.sectorToBlock(i);
                            for (int j = 0; j < mfc.getBlockCountInSector(i); ++j) {
                                byte[] blockData = mfc.readBlock(blockIndex+j);
                                sectorCheck.append("  Block <").append(blockIndex+j).append("> ")
                                        .append(encodeHexString(blockData)).append("\n");
                            }
                        } else {
                            sectorCheck.append("Sector <").append(i).append("> auth failed\n");
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "Try again and keep NFC tag below device", Toast.LENGTH_LONG).show();
                }
            } else if (tech.equals(MifareUltralight.class.getName())) {
                // Mifare Ultralight
                MifareUltralight mful = MifareUltralight.get(tag);
                switch (mful.getType()) {
                    case MifareUltralight.TYPE_ULTRALIGHT:
                        cardType.append("Ultralight");
                        break;

                    case MifareUltralight.TYPE_ULTRALIGHT_C:
                        cardType.append("Ultralight C");
                        break;

                    case MifareUltralight.TYPE_UNKNOWN:
                        cardType.append("Unknown");
                        break;
                }
            } else if (tech.equals(IsoDep.class.getName())) {
                // read card data of CardEmulator
                IsoDep isoDep = IsoDep.get(tag);
                try {
                    isoDep.connect();
                    byte [] resp = isoDep.transceive(hexStringToByteArray("00A4040007A0000002471002"));
                    cardResp.append(encodeHexString(resp));
                } catch (IOException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "Try again and keep card emulator phone below device", Toast.LENGTH_LONG).show();
                }
            }

            String [] techPkgFields = tech.split("\\.");
            if (techPkgFields.length > 0) {
                final String techName = techPkgFields[techPkgFields.length-1];
                if (0 == idx++) {
                    technologiesAvailable.append(techName);
                } else {
                    technologiesAvailable.append(", ").append(techName);
                }
            }
        }

        nfcInfo.append("\n").append(technologiesAvailable).append("\n")
                .append("\n").append(cardType).append("\n")
                .append("\n").append(cardResp).append("\n");

        // NDEF Messages
        StringBuilder sbNdefMessages = new StringBuilder("NDEF Messages: \n");
        Parcelable[] rawMessages = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
        if (rawMessages != null) {
            NdefMessage[] messages = new NdefMessage[rawMessages.length];
            for (int i = 0; i < rawMessages.length; ++i) {
                messages[i] = (NdefMessage) rawMessages[i];
            }

            for (NdefMessage message : messages) {
                for (NdefRecord record : message.getRecords()) {
                    if (record.getTnf() == NdefRecord.TNF_WELL_KNOWN) {
                        if (Arrays.equals(record.getType(), NdefRecord.RTD_TEXT)) {
                            try {
                                // NFC Forum "Text Record Type Definition" section 3.2.1.
                                byte[] payload = record.getPayload();
                                String textEncoding = ((payload[0] & 0200) == 0) ? "UTF-8" : "UTF-16";
                                int languageCodeLength = payload[0] & 0077;
                                String languageCode = new String(payload, 1, languageCodeLength, "US-ASCII");
                                String text = new String(payload, languageCodeLength + 1,
                                        payload.length - languageCodeLength - 1, textEncoding);
                                sbNdefMessages.append(" - ").append(languageCode).append(", ")
                                        .append(textEncoding).append(", ").append(text).append("\n");
                            } catch (UnsupportedEncodingException e) {
                                // should never happen unless we get a malformed tag.
                                throw new IllegalArgumentException(e);
                            }
                        }
                    }
                }
            }
        }
        nfcInfo.append("\n").append(sbNdefMessages).append("\n")
                .append("\n").append(sectorAndBlock).append("\n")
                .append("\n").append(sectorCheck).append("\n");

        mNfcInfoText.setText(nfcInfo.toString());
    }

    private String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    private String encodeHexString(byte[] byteArray) {
        StringBuilder hexStringBuffer = new StringBuilder();
        for (byte aByteArray : byteArray) {
            hexStringBuffer.append(byteToHex(aByteArray));
        }
        return hexStringBuffer.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
