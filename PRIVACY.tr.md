# Gizlilik

Bu sayfa, foSSH'ın bu sitede neyi, nasıl topladığını ve bunun neyi koruyup neyi korumadığını sade bir dille anlatır. foSSH çalıştıran bir site sahibi, bu sayfayı (veya bir özetini) kendi gizlilik sayfasına kopyalayabilir — sonda site sahipleri için bir not var.

## Ne toplanır

Bir sayfayı ziyaret ettiğinizde veya izlenen bir eylemi tetiklediğinizde, foSSH şunları kaydedebilir:

- sayfa yolu (ör. `/blog/merhaba`), sorgu parametreleriyle birlikte tam URL değil
- varsa, geldiğiniz site
- tarayıcı ailesi, işletim sistemi ailesi ve cihaz türü (masaüstü / mobil / tablet) — kaba kategoriler olarak, tarayıcınızın tam sürümü ya da bir parmak izi değil
- IP adresinizden çıkarılan ülkeniz — bundan daha kesin hiçbir şey değil
- ziyaret zamanı
- adlandırılmış olaylar için (ör. "kayıt oldu", "ödemeyi tamamladı"): olay adı ve, site sahibi öyle yapılandırdıysa, önceden onaylanmış az sayıda ek alan

## Kesinlikle toplanmayanlar

- **IP adresiniz asla saklanmaz.** Aşağıda anlatılan tek bir hesaplama için, isteğin işlendiği o an kullanılır ve hemen sonra atılır — kaydedilmez, bir dosyaya yazılmaz, "ihtiyaç olur belki" diye tutulmaz.
- **Çerez (cookie) yok.** Tarayıcınıza hiçbir şey yazılmaz, tarayıcınızdan da hiçbir şey okunmaz — `localStorage` yok, önbellek (cache) tabanlı numaralar yok.
- **Siteler arası takip yok.** foSSH'ın, farklı web sitelerindeki ziyaretlerinizi eşleştirebilecek merkezi bir sunucusu yoktur. Her foSSH kurulumu yalnızca kendisi için yapılandırılmış site(ler)i bilir.
- **Parmak izi (fingerprint) çıkarma yok.** Canvas parmak izi yok, yazı tipi (font) numaralandırması yok, ekran çözünürlüğü entropi yığma yok, TLS parmak izi yok.
- **Serbest metin yok.** Yazdığınız bir şeyin yanlışlıkla sızması mümkün değil — foSSH yalnızca site sahibinin önceden, açıkça izin verdiği olay adlarını ve alanları kaydeder.
- **Oturum kaydı yok.** Isı haritası (heatmap) yok, tuş vuruşu kaydı yok, fare hareketi takibi yok.

## Teknik terimsiz: döndürülen tuz (rotating salt)

"Kaç farklı kişi ziyaret etti" sayısını, kimin ziyaret ettiğini saklamadan sayabilmek için, foSSH veritabanına herhangi bir şey dokunmadan önce IP adresinizi ve tarayıcı kategorinizi bir matematiksel karıştırma fonksiyonundan ("özet" / hash) geçirir. Bu karıştırma, her gün değişen ve hiçbir yere kalıcı olarak yazılmayan rastgele bir malzeme kullanır — "tuz" (salt).

**Bunun koruduğu şey:** karıştırılmış sonuç, gerçek IP adresinize geri çevrilemez. Tuz her gün değiştiği için, aynı kişinin pazartesi ve salı günü yaptığı ziyaretler tamamen farklı, birbiriyle eşleştirilemeyen iki değer üretir — böylece site sahibi bile "bu, dünkü ziyaretçiyle aynı kişi" diyemez; yalnızca "bugün N farklı ziyaretçi geldi" diyebilir.

**Bunun korumadığı şey:** aynı gün içinde bir sitenin sayfalarını iki kez ziyaret ederseniz, bu iki ziyaret aynı değere karışır, yani o günün sayıları için "aynı ziyaretçi, iki kez" olarak sayılabilir. Tuz ayrıca yalnızca bellekte veya bellek destekli bir dosya sisteminde tutulur (asla kalıcı bir diske yazılmaz) — bu takasın, sunucunun kendisi ele geçirilmişse ne anlama geldiği için `THREAT_MODEL.md`'ye bakın. Ve bu bir istatistik aracıdır, bir hukuki kalkan değil: neyin toplandığını azaltır, ama tek başına belirli bir kullanımı yasal hale getirmez — aşağıdaki site sahipleri notuna bakın.

## Sayılar, kişiler değil

foSSH, bir bireyi teşhis edebilecek kadar küçük hiçbir sayıyı raporlamayı da reddeder. Belirli bir sayfa, ülke veya tarayıcı kombinasyonunun belirli bir dönemde çok az ziyaretçisi varsa, foSSH o küçük sayıyı tek başına göstermek yerine genel bir "diğer" kovasına katar. Buna k-anonimlik denir ve bu yazılımın ürettiği her raporda geçerlidir — kapatılabilecek bir ayar değildir.

## Sinyallerinize saygı

Tarayıcınız `Do Not Track` veya Global Privacy Control sinyali gönderiyorsa, foSSH varsayılan olarak bu ziyareti tamamen devre dışı bırakılmış sayar: anonim biçimde bile hiçbir şey kaydedilmez.

## Site sahipleri için

foSSH çalıştırmak, tek başına sitenizi GDPR, KVKK, ePrivacy, CCPA veya başka bir mevzuata uygun hale getirmez — bu, daha az veri toplayan bir araçtır, neyin uygulandığını bilmenin yerine geçmez. Kurulumunuzun topladığı veriler için tek veri sorumlusu sizsinizdir; foSSH'ın yazarı ne veri sorumlusu ne de veri işleyendir, çünkü kurulumunuzun topladığı hiçbir veri yazara ulaşmaz (bkz. `tos.md`). Bu sayfayı kendi gizlilik politikanıza kopyalarsanız, gerçekte yapılandırdığınız şeye göre (hangi olayları ve alanları izin verdiğiniz, saklama süreniz vb.) uyarlayın — bu sayfa yazılımın varsayılanlarını ve garantilerini anlatır, sizin özel yapılandırmanızı değil.
