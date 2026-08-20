package pl.cybertarcza.local;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class MainActivity extends Activity {
    private static final int UNLOCK_REQUEST = 71;
    private final Map<String, String[]> layers = new LinkedHashMap<>();
    private SecureState state;
    private Set<String> completed;
    private TextView score;
    private ProgressBar progress;
    private boolean unlocked;
    private boolean authenticating;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(Color.rgb(6, 17, 15));
        getWindow().setNavigationBarColor(Color.rgb(6, 17, 15));
        state = new SecureState(this);
        defineLayers();
        requestUnlock();
    }

    @Override protected void onResume() {
        super.onResume();
        if (!unlocked && !authenticating) requestUnlock();
        else if (completed != null) refreshScore();
    }

    @Override protected void onStop() {
        super.onStop();
        if (!isChangingConfigurations()) {
            unlocked = false;
            completed = null;
        }
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != UNLOCK_REQUEST) return;
        authenticating = false;
        if (resultCode == RESULT_OK) {
            unlocked = true;
            completed = state.load();
            render();
        } else {
            finishAndRemoveTask();
        }
    }

    private void requestUnlock() {
        if (authenticating) return;
        KeyguardManager manager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        if (manager != null && manager.isDeviceSecure()) {
            authenticating = true;
            Intent intent = manager.createConfirmDeviceCredentialIntent("Odblokuj CyberTarcze", "Potwierdz blokade ekranu, aby otworzyc zaszyfrowane dane.");
            startActivityForResult(intent, UNLOCK_REQUEST);
        } else {
            showSecureLockRequired();
        }
    }

    private void showSecureLockRequired() {
        LinearLayout root = vertical(14);
        root.setPadding(dp(24), dp(40), dp(24), dp(40));
        root.setBackgroundColor(Color.rgb(6, 17, 15));
        TextView title = text("Wymagana blokada ekranu", 26, Color.WHITE);
        title.setTypeface(null, 1);
        root.addView(title);
        root.addView(text("Dla ochrony zaszyfrowanych danych ustaw PIN, haslo lub silna biometrie, a nastepnie wroc do CyberTarczy.", 15, Color.rgb(158, 184, 173)));
        Button settings = button("Otworz ustawienia blokady");
        settings.setOnClickListener(v -> safeStart(new Intent(Settings.ACTION_SECURITY_SETTINGS)));
        root.addView(settings);
        setContentView(root);
    }

    private void defineLayers() {
        layers.put("yubikey", new String[]{"Dwa klucze YubiKey / passkeys", "Klucz glowny i zapasowy dla poczty, Google i menedzera hasel."});
        layers.put("passwords", new String[]{"Unikalne hasla i Watchtower", "Menedzer hasel wykrywa powtorzenia, slabe hasla i znane naruszenia."});
        layers.put("breaches", new String[]{"Alerty Have I Been Pwned", "Monitoruj adresy e-mail i reaguj po nowym wycieku."});
        layers.put("windows", new String[]{"Windows 10/11 i Defender", "Aktualizacje, zapora, szyfrowanie, SmartScreen i kopia offline."});
        layers.put("play-protect", new String[]{"Play Protect i Advanced Protection", "Aktualizacje, blokada APK, ochrona USB/2G, gdy dostepna."});
        layers.put("router", new String[]{"Router Vectra", "WPA3/WPA2-AES, bez WPS, UPnP i zdalnego zarzadzania."});
        layers.put("iot-segment", new String[]{"Oddzielona siec dla 11 IoT", "Osobny VLAN lub siec gosci, bez dostepu IoT do komputera i telefonu."});
        layers.put("iot-lifecycle", new String[]{"Aktualizacje i hasla 11 IoT", "Bez hasel fabrycznych; zapisany producent, model, wersja i koniec wsparcia."});
        layers.put("android-privacy", new String[]{"Minimalne uprawnienia aplikacji", "Usuniety dostep do SMS, kontaktow, plikow, lokalizacji i dostepnosci, gdy nie jest potrzebny."});
        layers.put("eu-incidents", new String[]{"Proces incydentow GDPR / NIS2 / CRA", "Osoba odpowiedzialna, zegary 24 h i 72 h, dowody oraz raport koncowy."});
        layers.put("eu-vulnerabilities", new String[]{"Podatnosci, SBOM i aktualizacje CRA", "Skoordynowane ujawnianie, lista komponentow i poprawki przez okres wsparcia."});
        layers.put("backup", new String[]{"Zaszyfrowana kopia offline", "Regula 3-2-1 i nosnik odlaczony po wykonaniu kopii."});
    }

    private void render() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(6, 17, 15));
        LinearLayout root = vertical(20);
        root.setPadding(dp(20), dp(28), dp(20), dp(40));
        scroll.addView(root);

        TextView eyebrow = text("LOKALNIE · SZYFROWANE", 12, Color.rgb(156, 244, 200));
        TextView title = text("CyberTarcza", 34, Color.WHITE);
        title.setTypeface(null, 1);
        TextView copy = text("Warstwowa ochrona Androida 10+, Windowsa, kont i routera.", 15, Color.rgb(158, 184, 173));
        root.addView(eyebrow); root.addView(title); root.addView(copy);

        LinearLayout scoreCard = card();
        score = text("0 / 100", 29, Color.rgb(156, 244, 200));
        score.setTypeface(null, 1);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        progress.getProgressDrawable().setTint(Color.rgb(54, 217, 155));
        scoreCard.addView(text("WYNIK WDROZENIA", 11, Color.rgb(158, 184, 173)));
        scoreCard.addView(score);
        scoreCard.addView(progress, new LinearLayout.LayoutParams(-1, dp(8)));
        root.addView(scoreCard);

        for (Map.Entry<String, String[]> entry : layers.entrySet()) {
            LinearLayout panel = card();
            CheckBox box = new CheckBox(this);
            box.setText(entry.getValue()[0]);
            box.setTextColor(Color.WHITE);
            box.setTextSize(16);
            box.setFilterTouchesWhenObscured(true);
            box.setButtonTintList(android.content.res.ColorStateList.valueOf(Color.rgb(54, 217, 155)));
            box.setChecked(completed.contains(entry.getKey()));
            box.setOnCheckedChangeListener((button, checked) -> {
                if (checked) completed.add(entry.getKey()); else completed.remove(entry.getKey());
                state.save(completed);
                refreshScore();
            });
            TextView detail = text(entry.getValue()[1], 13, Color.rgb(158, 184, 173));
            panel.addView(box);
            panel.addView(detail);
            addAction(entry.getKey(), panel);
            root.addView(panel);
        }

        TextView privacy = text("Dane checklisty sa szyfrowane kluczem AES-256-GCM przechowywanym w Android Keystore. Aplikacja nie prosi o hasla i nie posiada uprawnien administratora urzadzenia.", 12, Color.rgb(112, 142, 132));
        root.addView(privacy);
        setContentView(scroll);
        refreshScore();
    }

    private void addAction(String id, LinearLayout panel) {
        if (id.equals("breaches")) panel.addView(linkButton("Otworz HIBP", "https://haveibeenpwned.com/NotifyMe"));
        if (id.equals("yubikey")) panel.addView(linkButton("Otworz ochrone konta Google", "https://myaccount.google.com/advanced-protection"));
        if (id.equals("passwords")) panel.addView(linkButton("Informacje o Watchtower", "https://support.1password.com/watchtower/"));
        if (id.equals("play-protect")) {
            Button button = button("Otworz ustawienia zabezpieczen");
            button.setOnClickListener(v -> safeStart(new Intent(Settings.ACTION_SECURITY_SETTINGS)));
            panel.addView(button);
        }
        if (id.equals("android-privacy")) {
            Button button = button("Otworz panel prywatnosci");
            button.setOnClickListener(v -> safeStart(new Intent(Settings.ACTION_PRIVACY_SETTINGS)));
            panel.addView(button);
        }
        if (id.equals("iot-segment") || id.equals("iot-lifecycle")) panel.addView(linkButton("Otworz pomoc Vectra", "https://www.vectra.pl/pomoc"));
        if (id.equals("router")) panel.addView(linkButton("Pomoc Vectra", "https://www.vectra.pl/pomoc"));
        if (id.equals("windows")) panel.addView(linkButton("Wsparcie Windows", "https://support.microsoft.com/windows"));
    }

    private Button linkButton(String label, String url) {
        Button button = button(label);
        button.setOnClickListener(v -> safeStart(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
        return button;
    }

    private Button button(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setFilterTouchesWhenObscured(true);
        button.setTextColor(Color.rgb(6, 32, 25));
        button.setBackgroundColor(Color.rgb(156, 244, 200));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, dp(46));
        params.topMargin = dp(12);
        button.setLayoutParams(params);
        return button;
    }

    private void safeStart(Intent intent) {
        try { startActivity(intent); } catch (Exception ignored) {}
    }

    private void refreshScore() {
        if (score == null || completed == null) return;
        int value = Math.round((completed.size() * 100f) / layers.size());
        score.setText(value + " / 100");
        progress.setProgress(value, true);
    }

    private LinearLayout vertical(int gap) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setShowDividers(LinearLayout.SHOW_DIVIDER_MIDDLE);
        layout.setDividerPadding(dp(gap));
        return layout;
    }

    private LinearLayout card() {
        LinearLayout card = vertical(8);
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        android.graphics.drawable.GradientDrawable background = new android.graphics.drawable.GradientDrawable();
        background.setColor(Color.rgb(13, 34, 29));
        background.setCornerRadius(dp(18));
        background.setStroke(dp(1), Color.rgb(34, 61, 53));
        card.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(14);
        card.setLayoutParams(params);
        return card;
    }

    private TextView text(String value, int size, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setLineSpacing(0, 1.2f);
        return view;
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
}
