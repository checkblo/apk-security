const areas = [
  { mark: "W", title: "Windows 10/11", copy: "Defender, zapora, szyfrowanie, aktualizacje i audyt tylko do odczytu.", score: "86%" },
  { mark: "A", title: "Android 10+", copy: "Play Protect, blokada APK, Find Hub i Advanced Protection, gdy dostępna.", score: "74%" },
  { mark: "R", title: "Router Vectra", copy: "WPA3/WPA2-AES, bez WPS, UPnP i zdalnego panelu.", score: "50%" },
  { mark: "@", title: "Konta", copy: "Passkeys, YubiKey, unikalne hasła i monitoring znanych wycieków.", score: "62%" },
];

export default function Home() {
  return (
    <main>
      <nav className="site-nav">
        <a className="site-brand" href="#top"><span>CT</span><strong>CyberTarcza <small>LOCAL</small></strong></a>
        <div className="nav-status"><i /> Dostęp tylko lokalny</div>
      </nav>
      <section id="top" className="hero">
        <div className="hero-copy">
          <p className="kicker">Warstwowa ochrona osobista</p>
          <h1>Bezpieczeństwo bez wysyłania Twoich danych.</h1>
          <p className="lead">Lokalne centrum ochrony dla Windowsa, Androida, routera i kont. Szyfrowany sejf, monitoring wycieków oraz bezpieczne audyty — uruchamiane we własnym Dockerze.</p>
          <div className="hero-actions"><a href="#architecture" className="primary-link">Zobacz architekturę</a><span>AES-256-GCM · scrypt · HTTPS</span></div>
        </div>
        <div className="hero-panel">
          <div className="hero-panel-top"><span>POZIOM WDROŻENIA</span><i>LIVE</i></div>
          <div className="hero-score"><strong>68</strong><span>/100</span></div>
          <div className="score-line"><span /></div>
          <h2>Solidna podstawa</h2>
          <p>Najpierw dokończ konfigurację routera i zapasowego klucza sprzętowego.</p>
          <div className="mini-metrics"><span><b>14</b> kontroli</span><span><b>4</b> obszary</span><span><b>0</b> trackerów</span></div>
        </div>
      </section>
      <section className="areas-section">
        <div className="section-title"><p className="kicker">Jeden pulpit</p><h2>Cztery powierzchnie ataku pod kontrolą</h2></div>
        <div className="areas-grid">
          {areas.map((area) => (
            <article className="area-tile" key={area.title}>
              <div><span className="area-mark">{area.mark}</span><strong>{area.score}</strong></div>
              <h3>{area.title}</h3><p>{area.copy}</p><div className="tile-line"><span style={{ width: area.score }} /></div>
            </article>
          ))}
        </div>
      </section>
      <section id="architecture" className="architecture">
        <div><p className="kicker">Bezpieczna domyślna konfiguracja</p><h2>Mała powierzchnia ataku. Dużo warstw.</h2></div>
        <div className="architecture-grid">
          <article><span>01</span><h3>Tylko localhost</h3><p>Port aplikacji jest przypięty do 127.0.0.1. Usługa nie jest wystawiona do internetu ani domowej sieci.</p></article>
          <article><span>02</span><h3>Szyfrowanie sejfu</h3><p>AES-256-GCM zapewnia poufność i wykrywa każdą zmianę danych. Klucz jest wyprowadzany pamięcioodpornym scrypt.</p></article>
          <article><span>03</span><h3>Kontenery bez uprawnień</h3><p>System plików tylko do odczytu, brak capabilities, limit procesów, pamięci i brak dostępu do Docker Socket.</p></article>
          <article><span>04</span><h3>Bez przechowywania haseł</h3><p>Aplikacja zapisuje checklisty, urządzenia i wyniki. Hasła są sprawdzane jednorazowo metodą k-anonimowości.</p></article>
        </div>
      </section>
      <section className="compatibility">
        <p>Kompatybilność</p>
        <div><strong>Windows 10/11</strong><strong>Android 10+</strong><strong>Docker Desktop</strong><strong>Xiaomi 14 Pro 5G</strong></div>
      </section>
    </main>
  );
}
