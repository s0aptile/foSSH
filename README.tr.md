# foSSH

Gizliliği koruyan, gömülebilir (embeddable) telemetri. Ziyaretçi verisini üçüncü bir tarafa göndermeden, kendi sunucunuzda site analitiği.

**Durum: açık alfa (`0.1.0-alpha.1`).** Çalışıyor, test edildi, henüz her yerde eksiksiz sertleştirilmiş değil — şu an neyin bittiğini, neyin sürmekte olduğunu görmek için `DURUM.md` dosyasına bakın; her önemsiz olmayan kararın gerekçesi için `DECISIONS.md`'ye bakın.

## Neden var

Temel site analitiği almanın alışıldık yolu, gösterge paneli sunabilmek için her ziyaretçinin trafiğini gören barındırılan (hosted) bir servistir — en büyük örneği Google Analytics, ama çoğu barındırılan seçenekte takas aynı şekildedir. foSSH bu takası yapmaz: kendi altyapınızda çalışır, ham ziyaretçi kimlikleri yerine k-anonimlik ve günlük döndürülen tuzlanmış (salted) özetler (hash) kullanır, ve merkezi bir servis olmadığı için siteler arasında ziyaretçileri eşleştirebilecek hiçbir yer yoktur. Tam konumlandırma için `RULES.md`'ye bakın — bunun, halihazırda kullandığınız başka bir şeyi (GA/GTM dahil) kaldırmayı gerektirmediği de dahil.

## Dağıtım şekilleri

- **CGI** — `fossh-cgi`, RFC 3875 CGI konuşan tek bir ikili (binary). Apache `mod_cgi` veya nginx üzerinde `fcgiwrap` ile çalışır.
- **Gömülü (FFI)** — `libfossh`, bir C ABI (`cdylib`/`staticlib`); Go, PHP, Ruby veya bir C fonksiyonunu çağırabilen herhangi bir şeyin doğrudan içine bağlanır. Süreç yok, soket yok, açık port yok. Bkz. `bindings/`.
- **Paylaşımlı barındırma (shared hosting)** — kabuk (shell) erişimi yok, derlenmiş eklenti yok mu? PHP bağlamasının (binding) HTTP-uzak (remote) taşıyıcısı, düz HTTPS üzerinden başka bir yerde çalıştırdığınız bir foSSH örneğiyle konuşur. Bkz. `docs/INTEGRATION-php.md`.
- **Fedora-yerel (native)** — `sudo dnf install fossh` (sürmekte — bkz. `DURUM.md`'nin şu anki bölümü): bir OCaml bekçi (watchdog) süreci, sertleştirilmiş systemd birimleri, SELinux sınırlaması ve yerel bir TUI yönetim/kurulum sihirbazı (`fossh-tui`).

## Hızlı başlangıç (kaynaktan derleme)

```
cargo build --release --workspace
./target/release/fossh init
./target/release/fossh site create site-adim --allow pageview,signup
```

Son komut, bir kerelik bir yazma anahtarı (write key) yazdırır — bu, her bağlama/taşıyıcının kimlik doğrulamak için kullandığı kimlik bilgisidir. Nasıl dağıttığınıza uygun entegrasyon kılavuzu için `docs/` dizinine bakın (`INTEGRATION-php.md`, `DEPLOY-nginx-cloudflare-tunnel.md` ve zamanla eklenecek diğerleri).

## Gizlilik ve güvenlik

`THREAT_MODEL.md` ve `PRIVACY.md`, bu projenin kendini bağlı tuttuğu değişmezleri (invariant) kapsar (k-anonimlik eşikleri, tuzlanmış ziyaretçi özetleme, siteler arası eşleştirme yok, `Set-Cookie` yok, alım (ingest) yolundan sıfır giden ağ erişimi) — güncel durum için `DURUM.md`'ye bakın. Bu arada, gerçekte neyin uygulandığının ve nedeninin yetkili kaydı `DECISIONS.md`'nin ADR günlüğüdür.

## Lisans

Tercihinize göre [Apache-2.0](LICENSE-APACHE) veya [MIT](LICENSE-MIT) ile çift lisanslı.

## Bağış

foSSH, Monero bağışı kabul eder:

```
87NdV4EUcpQWsBR77L4PdCcWZjxhxcy91YGH1hJCdeXU7ERZrwwRZYT843gCojF7wsWfTUm8zH83BRNA7DTLdh9xC8pxnmZ
```
