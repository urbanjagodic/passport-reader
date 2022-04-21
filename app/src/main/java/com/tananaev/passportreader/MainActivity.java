/*
 * Copyright 2016 - 2020 Anton Tananaev (anton.tananaev@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.tananaev.passportreader;

import android.content.Context;
import android.graphics.Bitmap;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.snackbar.Snackbar;

import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.Certificate;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;

import org.jmrtd.lds.PACEInfo;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.jmrtd.PassportService.CAN_PACE_KEY_REFERENCE;
import static org.jmrtd.PassportService.DEFAULT_MAX_BLOCKSIZE;
import static org.jmrtd.PassportService.NORMAL_MAX_TRANCEIVE_LENGTH;

@RequiresApi(api = Build.VERSION_CODES.KITKAT)
public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();
    private View mainLayout;
    private View loadingLayout;

    private Button readPassportButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        readPassportButton = findViewById(R.id.readPassport);
        mainLayout = findViewById(R.id.main_layout);

        readPassportButton.setOnClickListener(v -> {

            Log.i("nfc", "Clicked read passport");

            Context myctx = getApplicationContext();

            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(myctx);
            if (adapter != null) {
                Log.i("nfc", "adapter is not null");

                adapter.enableReaderMode(MainActivity.this, new NfcAdapter.ReaderCallback() {
                    @Override
                    public void onTagDiscovered(Tag tag) {
                        Log.i("nfc", "TAG: " + tag.toString());
                        if (Arrays.asList(tag.getTechList()).contains("android.nfc.tech.IsoDep")) {
                            Log.i("nfc", "here");
                            // BACSPEC only for MRZ
                            //BACKeySpec bacKey = new BACKey(passportNumber, birthDate, expirationDate);
                            // using CAN authentication
                            PACEKeySpec canKey = new PACEKeySpec("159726", CAN_PACE_KEY_REFERENCE);

                            ReadDataClass readDataClass = new ReadDataClass(IsoDep.get(tag), canKey);
                            String result = readDataClass.readPersonalData();
                            Log.i("nfc", "result: " + result);

                            disableReaderMode();
                        }
                    }
                }, 1, null);
            }
        });
    }

    private void disableReaderMode() {
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableReaderMode(this);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
//        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
//        if (adapter != null) {
//        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableReaderMode(this);
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter != null) {
            adapter.disableReaderMode(this);
        }
    }

    private static String convertDate(String input) {
        if (input == null) {
            return null;
        }
        try {
            return new SimpleDateFormat("yyMMdd", Locale.US)
                    .format(new SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(input));
        } catch (ParseException e) {
            Log.w(MainActivity.class.getSimpleName(), e);
            return null;
        }
    }

    private Calendar loadDate(EditText editText) {
        Calendar calendar = Calendar.getInstance();
        if (!editText.getText().toString().isEmpty()) {
            try {
                calendar.setTimeInMillis(new SimpleDateFormat("yyyy-MM-dd", Locale.US)
                        .parse(editText.getText().toString()).getTime());
            } catch (ParseException e) {
                Log.w(MainActivity.class.getSimpleName(), e);
            }
        }
        return calendar;
    }

    private class ReadDataClass {

        private IsoDep isoDep;
        private PACEKeySpec pacKey;

        public ReadDataClass(IsoDep isoDep, PACEKeySpec pacKey) {
            this.isoDep = isoDep;
            this.pacKey = pacKey;
        }

        private DG1File dg1File;
        private DG2File dg2File;
        private DG14File dg14File;
        private SODFile sodFile;
        private String imageBase64;
        private Bitmap bitmap;
        private boolean chipAuthSucceeded = false;
        private boolean passiveAuthSuccess = false;

        private byte[] dg14Encoded = new byte[0];

        private void doChipAuth(PassportService service) {
            try {
                CardFileInputStream dg14In = service.getInputStream(PassportService.EF_DG14);
                dg14Encoded = IOUtils.toByteArray(dg14In);
                ByteArrayInputStream dg14InByte = new ByteArrayInputStream(dg14Encoded);
                dg14File = new DG14File(dg14InByte);

                Collection<SecurityInfo> dg14FileSecurityInfos = dg14File.getSecurityInfos();
                for (SecurityInfo securityInfo : dg14FileSecurityInfos) {
                    if (securityInfo instanceof ChipAuthenticationPublicKeyInfo) {
                        ChipAuthenticationPublicKeyInfo publicKeyInfo = (ChipAuthenticationPublicKeyInfo) securityInfo;
                        BigInteger keyId = publicKeyInfo.getKeyId();
                        PublicKey publicKey = publicKeyInfo.getSubjectPublicKey();

                        Log.i("nfc", "Public key: " + publicKey.toString());
                        String oid = publicKeyInfo.getObjectIdentifier();
                        service.doEACCA(keyId, ChipAuthenticationPublicKeyInfo.ID_CA_ECDH_AES_CBC_CMAC_256, oid, publicKey);
                        chipAuthSucceeded = true;
                    }
                }
            }
            catch (Exception e) {
                Log.w(TAG, e);
            }
        }

        private void doPassiveAuth() {
            try {
                MessageDigest digest = MessageDigest.getInstance(sodFile.getDigestAlgorithm());

                Map<Integer,byte[]> dataHashes = sodFile.getDataGroupHashes();

                byte[] dg14Hash = new byte[0];
                if(chipAuthSucceeded) {
                    dg14Hash = digest.digest(dg14Encoded);
                }
                byte[] dg1Hash = digest.digest(dg1File.getEncoded());
                byte[] dg2Hash = digest.digest(dg2File.getEncoded());

                if(Arrays.equals(dg1Hash, dataHashes.get(1)) && Arrays.equals(dg2Hash, dataHashes.get(2)) && (!chipAuthSucceeded || Arrays.equals(dg14Hash, dataHashes.get(14)))) {
                    // We retrieve the CSCA from the german master list
                    ASN1InputStream asn1InputStream = new ASN1InputStream(getAssets().open("masterList"));
                    ASN1Primitive p;
                    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                    keystore.load(null, null);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    while((p = asn1InputStream.readObject()) != null) {
                        ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
                        if (asn1 == null || asn1.size() == 0) {
                            throw new IllegalArgumentException("null or empty sequence passed.");
                        }
                        if (asn1.size() != 2) {
                            throw new IllegalArgumentException("Incorrect sequence size: " + asn1.size());
                        }
                        ASN1Set certSet = ASN1Set.getInstance(asn1.getObjectAt(1));

                        for (int i = 0; i < certSet.size(); i++) {
                            Certificate certificate = Certificate.getInstance(certSet.getObjectAt(i));

                            byte[] pemCertificate = certificate.getEncoded();

                            java.security.cert.Certificate javaCertificate = cf.generateCertificate(new ByteArrayInputStream(pemCertificate));
                            keystore.setCertificateEntry(String.valueOf(i), javaCertificate);
                        }
                    }
                    List<X509Certificate> docSigningCertificates = sodFile.getDocSigningCertificates();
                    for (X509Certificate docSigningCertificate : docSigningCertificates) {
                        Log.i("nfc", "CERT: " + docSigningCertificate.toString());
                        docSigningCertificate.checkValidity();
                    }

                    // We check if the certificate is signed by a trusted CSCA
                    // TODO: verify if certificate is revoked
                    CertPath cp = cf.generateCertPath(docSigningCertificates);
                    PKIXParameters pkixParameters = new PKIXParameters(keystore);
                    pkixParameters.setRevocationEnabled(false);
                    CertPathValidator cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
                    cpv.validate(cp, pkixParameters);

                    String sodDigestEncryptionAlgorithm = sodFile.getDocSigningCertificate().getSigAlgName();

                    boolean isSSA = false;
                    if (sodDigestEncryptionAlgorithm.equals("SSAwithRSA/PSS")) {
                        sodDigestEncryptionAlgorithm = "SHA256withRSA/PSS";
                        isSSA = true;
                    }

                    Signature sign = Signature.getInstance(sodDigestEncryptionAlgorithm);
                    if (isSSA) {
                        sign.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    }

                    sign.initVerify(sodFile.getDocSigningCertificate());
                    sign.update(sodFile.getEContent());
                    passiveAuthSuccess = sign.verify(sodFile.getEncryptedDigest());
                }
            }
            catch (Exception e) {
                Log.w(TAG, e);
            }
        }


        private String readPersonalData() {

            try {
                CardService cardService = CardService.getInstance(isoDep);
                cardService.open();

                PassportService service = new PassportService(cardService, NORMAL_MAX_TRANCEIVE_LENGTH, DEFAULT_MAX_BLOCKSIZE, false, false);
                service.open();

                boolean paceSucceeded = false;
                try {
                    CardAccessFile cardAccessFile = new CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS));
                    Collection<SecurityInfo> securityInfoCollection = cardAccessFile.getSecurityInfos();
                    for (SecurityInfo securityInfo : securityInfoCollection) {
                        if (securityInfo instanceof PACEInfo) {
                            PACEInfo paceInfo = (PACEInfo) securityInfo;
                            service.doPACE(pacKey, paceInfo.getObjectIdentifier(), PACEInfo.toParameterSpec(paceInfo.getParameterId()), null);
                            paceSucceeded = true;
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, e);
                }

                service.sendSelectApplet(paceSucceeded);

                if (!paceSucceeded) {
                    try {
                        service.getInputStream(PassportService.EF_COM).read();
                    } catch (Exception e) {
                        service.doBAC(pacKey);
                    }
                }

                CardFileInputStream dg1In = service.getInputStream(PassportService.EF_DG1);
                dg1File = new DG1File(dg1In);

                CardFileInputStream dg2In = service.getInputStream(PassportService.EF_DG2);
                dg2File = new DG2File(dg2In);

                CardFileInputStream sodIn = service.getInputStream(PassportService.EF_SOD);
                sodFile = new SODFile(sodIn);

//                // We perform Chip Authentication using Data Group 14
//                doChipAuth(service);
//
//                // Then Passive Authentication using SODFile
//                doPassiveAuth();

                List<FaceImageInfo> allFaceImageInfos = new ArrayList<>();
                List<FaceInfo> faceInfos = dg2File.getFaceInfos();
                for (FaceInfo faceInfo : faceInfos) {
                    allFaceImageInfos.addAll(faceInfo.getFaceImageInfos());
                }

                if (!allFaceImageInfos.isEmpty()) {
                    FaceImageInfo faceImageInfo = allFaceImageInfos.iterator().next();

                    int imageLength = faceImageInfo.getImageLength();
                    DataInputStream dataInputStream = new DataInputStream(faceImageInfo.getImageInputStream());
                    byte[] buffer = new byte[imageLength];
                    dataInputStream.readFully(buffer, 0, imageLength);
                    InputStream inputStream = new ByteArrayInputStream(buffer, 0, imageLength);

                    bitmap = ImageUtil.decodeImage(
                            MainActivity.this, faceImageInfo.getMimeType(), inputStream);
                    imageBase64 = Base64.encodeToString(buffer, Base64.DEFAULT);
                }

            } catch (Exception e) {
            }

            MRZInfo mrzInfo = dg1File.getMRZInfo();

            String resultMessage = String.format("DOB: %s, DOE: %s, GENDER: %s, STATE: %s, DOC_CODE: %s, DOC_NUM: %s, DOC_TYPE %s, " +
                            "NATIONALITY: %s, NAME: %s, LASTNAME: %s, PERSONAL_NUMBER: %s, OPTIONAL_DATA_1: %s, OPTIONAL_DATA_2: %s",
                    mrzInfo.getDateOfBirth(), mrzInfo.getDateOfExpiry(), mrzInfo.getGender().name(), mrzInfo.getIssuingState(),
                    mrzInfo.getDocumentCode(), mrzInfo.getDocumentNumber(), mrzInfo.getDocumentType(),
                    mrzInfo.getNationality(), mrzInfo.getSecondaryIdentifier().replace("<", " ").trim(),
                    mrzInfo.getPrimaryIdentifier().replace("<", " ").trim(), mrzInfo.getPersonalNumber(),
                    mrzInfo.getOptionalData1(), mrzInfo.getOptionalData2());
            return resultMessage;
        }
//                if (bitmap != null) {
//                    if (encodePhotoToBase64) {
//                        intent.putExtra(ResultActivity.KEY_PHOTO_BASE64, imageBase64);
//                    } else {
//                        double ratio = 320.0 / bitmap.getHeight();
//                        int targetHeight = (int) (bitmap.getHeight() * ratio);
//                        int targetWidth = (int) (bitmap.getWidth() * ratio);
//
//                        intent.putExtra(ResultActivity.KEY_PHOTO,
//                            Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, false));
//                    }
//                }
    }
}
