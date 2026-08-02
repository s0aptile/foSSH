# foSSH

Gizliliği koruyan, gömülebilir (embeddable) telemetri. Ziyaretçi verisini üçüncü bir tarafa göndermeden, kendi sunucunuzda site analitiği.

**Durum: açık alfa (`0.1.0-alpha.1`).** Çalışıyor, test edildi, henüz her yerde eksiksiz sertleştirilmiş değil — şu an neyin bittiğini, neyin sürmekte olduğunu görmek için `dev/DURUM.md` dosyasına bakın; her önemsiz olmayan kararın gerekçesi için `DECISIONS.md`'ye bakın.

## Neden var

Temel site analitiği almanın alışıldık yolu, gösterge paneli sunabilmek için her ziyaretçinin trafiğini gören barındırılan (hosted) bir servistir — en büyük örneği Google Analytics, ama çoğu barındırılan seçenekte takas aynı şekildedir. foSSH bu takası yapmaz: kendi altyapınızda çalışır, ham ziyaretçi kimlikleri yerine k-anonimlik ve günlük döndürülen tuzlanmış (salted) özetler (hash) kullanır, ve merkezi bir servis olmadığı için siteler arasında ziyaretçileri eşleştirebilecek hiçbir yer yoktur. Tam konumlandırma için `RULES.md`'ye bakın — bunun, halihazırda kullandığınız başka bir şeyi (GA/GTM dahil) kaldırmayı gerektirmediği de dahil.

## Dağıtım şekilleri

- **CGI** — `fossh-cgi`, RFC 3875 CGI konuşan tek bir ikili (binary). Apache `mod_cgi` veya nginx üzerinde `fcgiwrap` ile çalışır.
- **FastCGI** — `fossh-fcgi`, bir Unix soketi üzerinden doğrudan FastCGI konuşan kalıcı (persistent) bir süreç; her istek için yeni bir süreçten daha yüksek verim gereken dağıtımlar için. Havuzlamak (spool) yerine SQLite'a doğrudan toplu (batch) yazar, ve cron'a güvenmek yerine kendi saklama/vacuum bakımını kendi yürütür. Bkz. `packaging/systemd/fossh-fcgi.service`.
- **Gömülü (FFI)** — `libfossh`, bir C ABI (`cdylib`/`staticlib`); Go, PHP, Ruby veya bir C fonksiyonunu çağırabilen herhangi bir şeyin doğrudan içine bağlanır. Süreç yok, soket yok, açık port yok. Bkz. `bindings/`.
- **Paylaşımlı barındırma (shared hosting)** — kabuk (shell) erişimi yok, derlenmiş eklenti yok mu? PHP bağlamasının (binding) HTTP-uzak (remote) taşıyıcısı, düz HTTPS üzerinden başka bir yerde çalıştırdığınız bir foSSH örneğiyle konuşur. Bkz. `docs/INTEGRATION-php.md`.
- **Fedora-yerel (native)** — `sudo dnf install fossh` (sürmekte — bkz. `dev/DURUM.md`'nin şu anki bölümü): bir OCaml bekçi (watchdog) süreci, sertleştirilmiş systemd birimleri, SELinux sınırlaması ve yerel bir TUI yönetim/kurulum sihirbazı (`fossh-tui`).

## Hızlı başlangıç (kaynaktan derleme)

```
cargo build --release --workspace
./target/release/fossh init
./target/release/fossh site create site-adim --allow pageview,signup
```

Son komut, bir kerelik bir yazma anahtarı (write key) yazdırır — bu, her bağlama/taşıyıcının kimlik doğrulamak için kullandığı kimlik bilgisidir. Nasıl dağıttığınıza uygun entegrasyon kılavuzu için `docs/` dizinine bakın (`INTEGRATION-php.md`, `DEPLOY-apache.md`, `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md` ve zamanla eklenecek diğerleri).

## Gizlilik ve güvenlik

`THREAT_MODEL.md` ve `PRIVACY.md`, bu projenin kendini bağlı tuttuğu değişmezleri (invariant) kapsar (k-anonimlik eşikleri, tuzlanmış ziyaretçi özetleme, siteler arası eşleştirme yok, `Set-Cookie` yok, alım (ingest) yolundan sıfır giden ağ erişimi) — güncel durum için `dev/DURUM.md`'ye bakın. Bu arada, gerçekte neyin uygulandığının ve nedeninin yetkili kaydı `DECISIONS.md`'nin ADR günlüğüdür.

## Dokümantasyon dizini

Kök dizinde epey dosya var — çoğu, projenin kendi yasal/yazarlık ekinin (orijinal spesifikasyonun §19'u) gerektirmesi yüzünden burada duruyor, tıpkı `LICENSE`/`NOTICE`/`SECURITY.md` dosyalarının çoğu gerçek dünya deposunun kökünde araçların (GitHub dahil) onları bulabilmesi için durması gibi. Hepsinin haritası:

| Dosya | Ne işe yarar |
|---|---|
| `readme.md` | *Sürüm* (release) readme'si (zip kökü) — daha kısa, hızlı-başlangıç odaklı. Bu dosyadan ayrı. |
| `PRIVACY.md` / `PRIVACY.tr.md` | Yapıştırılabilir gizlilik sayfası metni, İngilizce ve Türkçe. |
| `README.md` | Bu dosyanın İngilizce aslı. |
| `THREAT_MODEL.md` | Varlıklar, tehdit aktörleri, neye karşı korunulduğu ve korunulmadığı, alfa uyarıları. |
| `tos.md` | Kullanım şartları ve sorumluluk reddi — yasal duruş, bir hizmet sözleşmesi değil. |
| `SECURITY.md` | Bir güvenlik açığı nasıl bildirilir. |
| `NOTICE` | Üçüncü taraf bağımlılık lisansları, üretilmiş, elle bakımı yapılmıyor. |
| `AUTHORS`, `LICENSE` | Tam olarak söyledikleri şey. |
| `RULES.md` | İsimlendirme, ton, kamuya açık/özel sınırı, platform desteği, konumlandırma. |
| `DECISIONS.md` | ADR günlüğü — önemsiz olmayan her seçim, ve nedeni. |
| `dev/` | Bu proje şu anda fiilen nasıl inşa ediliyor — bölüm durumu (`dev/DURUM.md`), geriye dönük değerlendirmeler. Son kullanıcı dokümantasyonu değil; onun için `docs/`'a bakın. |
| `docs/` | Dile ve web sunucusuna göre entegrasyon kılavuzları. |
| `docs/preview/` | Projenin diğer dağıtım yüzeylerinin geçtiği adversarial-review (çekişmeli inceleme) aşamasından henüz geçmemiş dağıtım katmanları — amaçlanan şekil, henüz incelenmiş/desteklenen bir yol değil. |
| `PUBLISH.md` | Gitignore'lu, dağıtılmıyor — yazarın kendi yayınlama kopyala-yapıştır sayfası. |
| `private-onlyauthor/` | Gitignore'lu, dağıtılmıyor — kimliği belli edici herhangi bir şey, ya da yazarın gözü için herhangi bir özel not. |

## Lisans

[MIT](LICENSE) lisansı altında lisanslıdır.

## Bağış

foSSH şu adreslerden bağış kabul eder:

- **Solana (SPL):** `J7wgrgySAVvWmreXiM51ig3rqY1vNnpdpvqZsHZLPfwD`
- **Neon (Neon EVM):** `0xEde8Dd4413b667269e3Df902C49532C2212475AF`
- **Monero** (önerilmez): `87NdV4EUcpQWsBR77L4PdCcWZjxhxcy91YGH1hJCdeXU7ERZrwwRZYT843gCojF7wsWfTUm8zH83BRNA7DTLdh9xC8pxnmZ`
