package main

import (
	"fmt"
	"os"
	"strings"
)

type ruleText struct{ title, what, todo string }

type catalog struct {
	scanning, noBrowsers, scanned, clean, cleanExt, worstNow, policyGroup string
	extCount, profileCount, profileCount1, cleanExt1                      string
	disabled, notLoaded, version, source, id, file, reported, threat, ref string
	alsoLow, listsUsed, pressEnter, nextSteps                             string
	steps                                                                 []string
	sources                                                               map[string]string
	sev                                                                   map[severity]string
	rules                                                                 map[string]ruleText
}

var en = &catalog{
	scanning:      "Scanning browser extensions",
	noBrowsers:    "No supported browser profiles were found on this computer.",
	scanned:       "Scanned %d extensions in %s (%s).",
	clean:         "Nothing to report. No known malicious extension and nothing installed in a risky way.",
	cleanExt:      "%d other extensions look fine.",
	cleanExt1:     "1 other extension looks fine.",
	policyGroup:   "Browser policy",
	extCount:      "extensions",
	profileCount:  "%d profiles",
	profileCount1: "1 profile",
	disabled:      "disabled",
	notLoaded:     "folder on disk, not loaded by the browser",
	version:       "version",
	source:        "installed",
	id:            "id",
	file:          "file",
	reported:      "reported",
	threat:        "type",
	ref:           "source",
	alsoLow:       "Also worth knowing:",
	listsUsed:     "Known bad list: %s.",
	pressEnter:    "Press Enter to close.",
	nextSteps:     "What to do now",
	steps: []string{
		"Remove the extension: open the browser's extensions page (chrome://extensions, edge://extensions, brave://extensions or about:addons) and click Remove.",
		"If it comes back after a restart, something on the computer reinstalls it. Run a malware scan and check the policy entries listed above.",
		"Change the passwords you typed in that browser while it was installed, starting with email and banking, and sign out of other sessions.",
		"Turn on two-factor login where you can. A stolen session cookie skips the password, so signing out everywhere matters.",
	},
	sources: map[string]string{
		srcStore: "from the store", srcExternal: "by another program", srcPolicy: "by policy",
		srcUnpacked: "unpacked (developer mode)", srcCommandLine: "from the command line",
		srcSideloaded: "by another program", srcTemporary: "temporarily", srcUnknown: "unknown",
	},
	sev: map[severity]string{critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW"},
	rules: map[string]ruleText{
		"EXT001": {"Known malicious extension",
			"This extension id is on a public list of extensions that stole data, hijacked searches or injected ads.",
			"Remove it now, then follow the steps at the end of this report."},
		"EXT002": {"Loaded from the command line",
			"The browser was started with --load-extension, which loads code that never went through a store. Malware such as ChromeLoader uses this trick.",
			"Check the browser shortcut and any scheduled task that starts the browser for --load-extension, remove it, then remove the extension."},
		"EXT003": {"Installed by a browser policy",
			"A policy forces this extension into the browser and hides the Remove button. Companies do this on work computers; adware does it too.",
			"If no company manages this computer, delete the policy entry shown here (needs admin) and remove the extension."},
		"EXT004": {"Loaded in developer mode",
			"This extension was loaded from a folder, not from a store, so nobody reviewed it.",
			"Keep it only if you build or trust it. Otherwise remove it and turn off developer mode."},
		"EXT005": {"Installed by another program",
			"A program on this computer added this extension instead of you installing it from the store.",
			"Make sure you know which program added it and that you want it."},
		"EXT006": {"Updates from a server outside the store",
			"The extension downloads its updates from a private server, so its owner can ship any code at any time with no store review.",
			"Remove it unless it is a company tool you expect."},
		"EXT007": {"Added by another program",
			"Firefox marks this add-on as installed by something other than you.",
			"Make sure you know where it came from."},
		"EXT008": {"Not signed by Mozilla",
			"Firefox normally refuses unsigned add-ons. One that runs anyway was installed around the normal checks.",
			"Remove it unless you build it yourself."},
		"EXT009": {"Temporary add-on",
			"Loaded through about:debugging. It disappears when Firefox closes.",
			"Fine if you are developing it."},
		"EXT010": {"Can read and change every website",
			"It runs on every site you open and can read what is on the page, including what you type, and change it.",
			"Normal for ad blockers and password managers. Keep it only if you trust the developer."},
		"EXT011": {"Can control the browser (debugger)",
			"The debugger permission lets it inspect and drive any tab, read network traffic and bypass most other protections.",
			"Very few extensions need this. Remove it unless you know why it has it."},
		"EXT012": {"Can route all your traffic (proxy)",
			"It can send every page you load through a server it chooses.",
			"Expected for VPN and proxy extensions only."},
		"EXT013": {"Can turn other extensions off",
			"The management permission lets it disable or remove other extensions, security ones included.",
			"Check that it really needs this."},
		"EXT014": {"Talks to a program on your computer",
			"Native messaging connects it to a desktop program outside the browser.",
			"Normal for password managers and download managers. Make sure the program is one you installed."},
		"EXT015": {"On an automated adware list",
			"An automated feed lists this extension as adware or a search hijacker, and no researcher report backs it up. Some mainstream extensions land here only because they change the default search engine.",
			"If you installed it on purpose and know the developer, it is probably fine. If you do not remember installing it, remove it."},
		"EXT020": {"Hard-coded Telegram or Discord upload",
			"The code contains a Telegram bot or Discord webhook address. Stealers use these to send stolen data out.",
			"Remove it and treat the browser's saved logins as exposed."},
		"EXT021": {"Runs code it downloads",
			"It fetches code from the internet and runs it, so what it does can change after it was reviewed.",
			"Remove it unless you trust the developer completely."},
		"EXT022": {"Obfuscated code",
			"Large parts of the code are scrambled so a reader cannot follow them. Store rules forbid this.",
			"Be suspicious, especially together with wide permissions."},
		"EXT023": {"Reads all cookies and talks to a server",
			"It reads every cookie in the browser and its code also sends requests to the internet. Cookies are your logged-in sessions.",
			"Keep it only if this is what it is for, such as a cookie manager you trust."},
	},
}

var tr = &catalog{
	scanning:      "Tarayıcı eklentileri taranıyor",
	noBrowsers:    "Bu bilgisayarda desteklenen bir tarayıcı profili bulunamadı.",
	scanned:       "%d eklenti, %s tarandı (%s).",
	clean:         "Raporlanacak bir şey yok. Bilinen zararlı eklenti yok, riskli şekilde kurulmuş eklenti de yok.",
	cleanExt:      "Diğer %d eklentide sorun görünmüyor.",
	cleanExt1:     "Diğer 1 eklentide sorun görünmüyor.",
	policyGroup:   "Tarayıcı politikası",
	extCount:      "eklenti",
	profileCount:  "%d profilde",
	profileCount1: "1 profilde",
	disabled:      "kapalı",
	notLoaded:     "diskte klasörü var, tarayıcı yüklemiyor",
	version:       "sürüm",
	source:        "kurulum",
	id:            "kimlik",
	file:          "dosya",
	reported:      "bildirildi",
	threat:        "tür",
	ref:           "kaynak",
	alsoLow:       "Bilmekte fayda var:",
	listsUsed:     "Zararlı listesi: %s.",
	pressEnter:    "Kapatmak için Enter'a bas.",
	nextSteps:     "Şimdi ne yapmalı",
	steps: []string{
		"Eklentiyi kaldır: tarayıcının eklentiler sayfasını aç (chrome://extensions, edge://extensions, brave://extensions ya da about:addons) ve Kaldır'a bas.",
		"Yeniden başlatınca geri geliyorsa bilgisayardaki bir program onu tekrar kuruyor. Virüs taraması yap ve yukarıdaki politika kayıtlarına bak.",
		"Eklenti kuruluyken o tarayıcıda girdiğin şifreleri değiştir, önce e-posta ve banka. Diğer oturumlardan çıkış yap.",
		"Yapabildiğin her yerde iki adımlı girişi aç. Çalınan oturum çerezi şifreye gerek bırakmaz, bu yüzden her yerden çıkış yapmak önemli.",
	},
	sources: map[string]string{
		srcStore: "mağazadan", srcExternal: "başka bir program", srcPolicy: "politika ile",
		srcUnpacked: "klasörden (geliştirici modu)", srcCommandLine: "komut satırından",
		srcSideloaded: "başka bir program", srcTemporary: "geçici", srcUnknown: "bilinmiyor",
	},
	sev: map[severity]string{critical: "KRİTİK", high: "YÜKSEK", medium: "ORTA", low: "DÜŞÜK"},
	rules: map[string]ruleText{
		"EXT001": {"Bilinen zararlı eklenti",
			"Bu eklenti kimliği, veri çalan, aramaları ele geçiren ya da reklam basan eklentilerin herkese açık listesinde.",
			"Hemen kaldır, sonra raporun sonundaki adımları uygula."},
		"EXT002": {"Komut satırından yüklenmiş",
			"Tarayıcı --load-extension ile başlatılmış. Bu yol mağazadan hiç geçmemiş kodu yükler. ChromeLoader gibi zararlılar bu hileyi kullanır.",
			"Tarayıcı kısayolunda ve tarayıcıyı başlatan zamanlanmış görevlerde --load-extension var mı bak, kaldır, sonra eklentiyi sil."},
		"EXT003": {"Tarayıcı politikasıyla kurulmuş",
			"Bir politika bu eklentiyi zorla kuruyor ve Kaldır düğmesini gizliyor. Şirketler iş bilgisayarlarında bunu yapar, reklam yazılımları da yapar.",
			"Bu bilgisayarı bir şirket yönetmiyorsa burada görünen politika kaydını sil (yönetici izni gerekir) ve eklentiyi kaldır."},
		"EXT004": {"Geliştirici modunda yüklenmiş",
			"Bu eklenti mağazadan değil bir klasörden yüklenmiş, kimse incelememiş.",
			"Sadece kendin yazdıysan ya da güveniyorsan tut. Yoksa kaldır ve geliştirici modunu kapat."},
		"EXT005": {"Başka bir program kurmuş",
			"Bu eklentiyi sen mağazadan kurmamışsın, bilgisayardaki bir program eklemiş.",
			"Hangi programın eklediğini ve istediğin bir şey olduğunu doğrula."},
		"EXT006": {"Güncellemesini mağaza dışından alıyor",
			"Eklenti güncellemelerini kendi sunucusundan indiriyor. Sahibi istediği an mağaza incelemesi olmadan istediği kodu gönderebilir.",
			"Beklediğin bir şirket aracı değilse kaldır."},
		"EXT007": {"Başka bir program eklemiş",
			"Firefox bu eklentiyi senin dışında bir şeyin kurduğunu işaretlemiş.",
			"Nereden geldiğini bildiğinden emin ol."},
		"EXT008": {"Mozilla imzası yok",
			"Firefox imzasız eklentiyi normalde çalıştırmaz. Yine de çalışıyorsa normal kontroller atlanarak kurulmuş.",
			"Kendin geliştirmiyorsan kaldır."},
		"EXT009": {"Geçici eklenti",
			"about:debugging ile yüklenmiş. Firefox kapanınca gider.",
			"Geliştiriyorsan sorun yok."},
		"EXT010": {"Her siteyi okuyup değiştirebiliyor",
			"Açtığın her sitede çalışıyor. Sayfadakini, yazdıklarını da dahil okuyabilir ve değiştirebilir.",
			"Reklam engelleyici ve şifre yöneticilerinde normal. Geliştiricisine güveniyorsan tut."},
		"EXT011": {"Tarayıcıyı yönetebiliyor (debugger)",
			"Debugger izni her sekmeyi izlemesine ve yönetmesine, ağ trafiğini okumasına ve çoğu korumayı aşmasına izin verir.",
			"Bu izne ihtiyacı olan eklenti çok az. Nedenini bilmiyorsan kaldır."},
		"EXT012": {"Bütün trafiği yönlendirebiliyor (proxy)",
			"Açtığın her sayfayı kendi seçtiği bir sunucu üzerinden geçirebilir.",
			"Sadece VPN ve proxy eklentilerinde beklenir."},
		"EXT013": {"Diğer eklentileri kapatabiliyor",
			"Management izni, güvenlik eklentileri dahil diğer eklentileri kapatmasına ya da silmesine izin verir.",
			"Bu izne gerçekten ihtiyacı var mı kontrol et."},
		"EXT014": {"Bilgisayardaki bir programla konuşuyor",
			"Native messaging onu tarayıcı dışındaki bir masaüstü programına bağlar.",
			"Şifre yöneticisi ve indirme yöneticilerinde normal. Programın senin kurduğun bir program olduğundan emin ol."},
		"EXT015": {"Otomatik reklam yazılımı listesinde",
			"Otomatik bir liste bu eklentiyi reklam yazılımı ya da arama ele geçirici sayıyor, ama bunu destekleyen bir araştırma raporu yok. Bazı bilinen eklentiler sadece varsayılan arama motorunu değiştirdiği için bu listeye düşüyor.",
			"Bilerek kurduysan ve geliştiricisini tanıyorsan büyük ihtimalle sorun yok. Kurduğunu hatırlamıyorsan kaldır."},
		"EXT020": {"Koda gömülü Telegram ya da Discord gönderimi",
			"Kodda bir Telegram botu ya da Discord webhook adresi var. Bilgi çalan zararlılar çaldıklarını bunlarla dışarı yollar.",
			"Kaldır ve tarayıcıdaki kayıtlı girişleri ele geçmiş say."},
		"EXT021": {"İndirdiği kodu çalıştırıyor",
			"İnternetten kod çekip çalıştırıyor. Yani incelendikten sonra ne yaptığı değişebilir.",
			"Geliştiricisine tamamen güvenmiyorsan kaldır."},
		"EXT022": {"Karıştırılmış kod",
			"Kodun büyük kısmı okunmasın diye karıştırılmış. Mağaza kuralları bunu yasaklar.",
			"Şüpheyle yaklaş, özellikle geniş izinlerle birlikteyse."},
		"EXT023": {"Bütün çerezleri okuyup sunucuyla konuşuyor",
			"Tarayıcıdaki bütün çerezleri okuyor ve kodu internete istek de gönderiyor. Çerezler açık oturumlarındır.",
			"Bu onun asıl işiyse (güvendiğin bir çerez yöneticisi gibi) tut, değilse kaldır."},
	},
}

var messages = map[string]*catalog{"en": en, "tr": tr}

// plural picks the singular form for one, the "%d" form otherwise.
func (c *catalog) plural(many, one string, n int) string {
	if n == 1 {
		return one
	}
	return fmt.Sprintf(many, n)
}

// detectLang picks Turkish when the system is set to Turkish, English otherwise.
func detectLang() string {
	for _, k := range []string{"EXTSWEEP_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); v != "" {
			if strings.HasPrefix(v, "tr") {
				return "tr"
			}
			return "en"
		}
	}
	if systemTurkish() {
		return "tr"
	}
	return "en"
}
