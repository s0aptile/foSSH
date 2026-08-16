#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BrowserFamily {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Opera,
    SamsungInternet,
    Bot,
    Other,
}

impl BrowserFamily {

    pub fn as_u8(self) -> u8 {
        match self {
            BrowserFamily::Chrome => 0,
            BrowserFamily::Firefox => 1,
            BrowserFamily::Safari => 2,
            BrowserFamily::Edge => 3,
            BrowserFamily::Opera => 4,
            BrowserFamily::SamsungInternet => 5,
            BrowserFamily::Bot => 6,
            BrowserFamily::Other => 7,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => BrowserFamily::Chrome,
            1 => BrowserFamily::Firefox,
            2 => BrowserFamily::Safari,
            3 => BrowserFamily::Edge,
            4 => BrowserFamily::Opera,
            5 => BrowserFamily::SamsungInternet,
            6 => BrowserFamily::Bot,
            _ => BrowserFamily::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OsFamily {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
    Bot,
    Other,
}

impl OsFamily {
    pub fn as_u8(self) -> u8 {
        match self {
            OsFamily::Windows => 0,
            OsFamily::MacOs => 1,
            OsFamily::Linux => 2,
            OsFamily::Android => 3,
            OsFamily::Ios => 4,
            OsFamily::Bot => 5,
            OsFamily::Other => 6,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => OsFamily::Windows,
            1 => OsFamily::MacOs,
            2 => OsFamily::Linux,
            3 => OsFamily::Android,
            4 => OsFamily::Ios,
            5 => OsFamily::Bot,
            _ => OsFamily::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviceClass {
    Desktop,
    Mobile,
    Tablet,
    Bot,
    Unknown,
}

impl DeviceClass {
    pub fn as_u8(self) -> u8 {
        match self {
            DeviceClass::Desktop => 0,
            DeviceClass::Mobile => 1,
            DeviceClass::Tablet => 2,
            DeviceClass::Bot => 3,
            DeviceClass::Unknown => 4,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => DeviceClass::Desktop,
            1 => DeviceClass::Mobile,
            2 => DeviceClass::Tablet,
            3 => DeviceClass::Bot,
            _ => DeviceClass::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaBuckets {
    pub browser: BrowserFamily,
    pub os: OsFamily,
    pub device: DeviceClass,
}

const BOT_TOKENS: &[&str] = &[
    "bot",
    "spider",
    "crawl",
    "slurp",
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "libwww-perl",
    "httpclient",
    "facebookexternalhit",
    "bingpreview",
    "headlesschrome",
    "phantomjs",
    "pingdom",
    "uptimerobot",
    "monitoring",
];

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn is_bot(ua: &str) -> bool {
    BOT_TOKENS.iter().any(|tok| contains_ci(ua, tok))
}

fn browser_family(ua: &str) -> BrowserFamily {

    if contains_ci(ua, "edg/") || contains_ci(ua, "edga/") || contains_ci(ua, "edgios/") {
        BrowserFamily::Edge
    } else if contains_ci(ua, "samsungbrowser/") {
        BrowserFamily::SamsungInternet
    } else if contains_ci(ua, "opr/") || contains_ci(ua, "opera") {
        BrowserFamily::Opera
    } else if contains_ci(ua, "firefox/") || contains_ci(ua, "fxios/") {
        BrowserFamily::Firefox
    } else if contains_ci(ua, "chrome/") || contains_ci(ua, "crios/") {
        BrowserFamily::Chrome
    } else if contains_ci(ua, "safari/") {
        BrowserFamily::Safari
    } else {
        BrowserFamily::Other
    }
}

fn os_family(ua: &str) -> OsFamily {
    if contains_ci(ua, "windows") {
        OsFamily::Windows
    } else if contains_ci(ua, "iphone") || contains_ci(ua, "ipad") || contains_ci(ua, "ipod") {
        OsFamily::Ios
    } else if contains_ci(ua, "android") {
        OsFamily::Android
    } else if contains_ci(ua, "mac os x") || contains_ci(ua, "macintosh") {
        OsFamily::MacOs
    } else if contains_ci(ua, "linux") {
        OsFamily::Linux
    } else {
        OsFamily::Other
    }
}

fn device_class(ua: &str) -> DeviceClass {

    if contains_ci(ua, "ipad")
        || contains_ci(ua, "tablet")
        || (contains_ci(ua, "android") && !contains_ci(ua, "mobile"))
    {
        DeviceClass::Tablet
    } else if contains_ci(ua, "iphone") || contains_ci(ua, "ipod") || contains_ci(ua, "mobile") {
        DeviceClass::Mobile
    } else if contains_ci(ua, "windows")
        || contains_ci(ua, "macintosh")
        || contains_ci(ua, "mac os x")
        || contains_ci(ua, "x11")
        || contains_ci(ua, "linux")
    {
        DeviceClass::Desktop
    } else {
        DeviceClass::Unknown
    }
}

pub fn bucket_user_agent(ua: &str) -> UaBuckets {
    if ua.trim().is_empty() {
        return UaBuckets {
            browser: BrowserFamily::Other,
            os: OsFamily::Other,
            device: DeviceClass::Unknown,
        };
    }
    if is_bot(ua) {
        return UaBuckets {
            browser: BrowserFamily::Bot,
            os: OsFamily::Bot,
            device: DeviceClass::Bot,
        };
    }
    UaBuckets {
        browser: browser_family(ua),
        os: os_family(ua),
        device: device_class(ua),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_family_code_roundtrip() {
        for b in [
            BrowserFamily::Chrome,
            BrowserFamily::Firefox,
            BrowserFamily::Safari,
            BrowserFamily::Edge,
            BrowserFamily::Opera,
            BrowserFamily::SamsungInternet,
            BrowserFamily::Bot,
            BrowserFamily::Other,
        ] {
            assert_eq!(BrowserFamily::from_u8(b.as_u8()), b);
        }
    }

    #[test]
    fn os_family_code_roundtrip() {
        for o in [
            OsFamily::Windows,
            OsFamily::MacOs,
            OsFamily::Linux,
            OsFamily::Android,
            OsFamily::Ios,
            OsFamily::Bot,
            OsFamily::Other,
        ] {
            assert_eq!(OsFamily::from_u8(o.as_u8()), o);
        }
    }

    #[test]
    fn device_class_code_roundtrip() {
        for d in [
            DeviceClass::Desktop,
            DeviceClass::Mobile,
            DeviceClass::Tablet,
            DeviceClass::Bot,
            DeviceClass::Unknown,
        ] {
            assert_eq!(DeviceClass::from_u8(d.as_u8()), d);
        }
    }

    #[test]
    fn unrecognized_code_decodes_to_the_neutral_fallback() {
        assert_eq!(BrowserFamily::from_u8(255), BrowserFamily::Other);
        assert_eq!(OsFamily::from_u8(255), OsFamily::Other);
        assert_eq!(DeviceClass::from_u8(255), DeviceClass::Unknown);
    }

    const CHROME_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    const CHROME_ANDROID_PHONE: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";
    const CHROME_ANDROID_TABLET: &str = "Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    const SAFARI_IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
    const SAFARI_IPAD: &str = "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
    const SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
    const FIREFOX_LINUX: &str =
        "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0";
    const EDGE_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0";
    const OPERA_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0";
    const SAMSUNG_ANDROID: &str = "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/115.0.0.0 Mobile Safari/537.36";
    const GOOGLEBOT: &str =
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    const CURL: &str = "curl/8.7.1";

    #[test]
    fn chrome_windows_desktop() {
        let b = bucket_user_agent(CHROME_WINDOWS);
        assert_eq!(b.browser, BrowserFamily::Chrome);
        assert_eq!(b.os, OsFamily::Windows);
        assert_eq!(b.device, DeviceClass::Desktop);
    }

    #[test]
    fn chrome_android_phone() {
        let b = bucket_user_agent(CHROME_ANDROID_PHONE);
        assert_eq!(b.browser, BrowserFamily::Chrome);
        assert_eq!(b.os, OsFamily::Android);
        assert_eq!(b.device, DeviceClass::Mobile);
    }

    #[test]
    fn chrome_android_tablet_without_mobile_token() {
        let b = bucket_user_agent(CHROME_ANDROID_TABLET);
        assert_eq!(b.os, OsFamily::Android);
        assert_eq!(b.device, DeviceClass::Tablet);
    }

    #[test]
    fn safari_iphone() {
        let b = bucket_user_agent(SAFARI_IPHONE);
        assert_eq!(b.browser, BrowserFamily::Safari);
        assert_eq!(b.os, OsFamily::Ios);
        assert_eq!(b.device, DeviceClass::Mobile);
    }

    #[test]
    fn safari_ipad_is_tablet() {
        let b = bucket_user_agent(SAFARI_IPAD);
        assert_eq!(b.os, OsFamily::Ios);
        assert_eq!(b.device, DeviceClass::Tablet);
    }

    #[test]
    fn safari_mac_desktop() {
        let b = bucket_user_agent(SAFARI_MAC);
        assert_eq!(b.browser, BrowserFamily::Safari);
        assert_eq!(b.os, OsFamily::MacOs);
        assert_eq!(b.device, DeviceClass::Desktop);
    }

    #[test]
    fn firefox_linux_desktop() {
        let b = bucket_user_agent(FIREFOX_LINUX);
        assert_eq!(b.browser, BrowserFamily::Firefox);
        assert_eq!(b.os, OsFamily::Linux);
        assert_eq!(b.device, DeviceClass::Desktop);
    }

    #[test]
    fn edge_not_misclassified_as_chrome() {
        let b = bucket_user_agent(EDGE_WINDOWS);
        assert_eq!(b.browser, BrowserFamily::Edge);
        assert_eq!(b.os, OsFamily::Windows);
        assert_eq!(b.device, DeviceClass::Desktop);
    }

    #[test]
    fn opera_not_misclassified_as_chrome() {
        let b = bucket_user_agent(OPERA_WINDOWS);
        assert_eq!(b.browser, BrowserFamily::Opera);
    }

    #[test]
    fn samsung_internet_mobile() {
        let b = bucket_user_agent(SAMSUNG_ANDROID);
        assert_eq!(b.browser, BrowserFamily::SamsungInternet);
        assert_eq!(b.os, OsFamily::Android);
        assert_eq!(b.device, DeviceClass::Mobile);
    }

    #[test]
    fn googlebot_is_bot() {
        let b = bucket_user_agent(GOOGLEBOT);
        assert_eq!(b.browser, BrowserFamily::Bot);
        assert_eq!(b.os, OsFamily::Bot);
        assert_eq!(b.device, DeviceClass::Bot);
    }

    #[test]
    fn curl_is_bot() {
        let b = bucket_user_agent(CURL);
        assert_eq!(b.browser, BrowserFamily::Bot);
    }

    #[test]
    fn empty_is_unknown_not_bot() {
        let b = bucket_user_agent("");
        assert_eq!(b.browser, BrowserFamily::Other);
        assert_eq!(b.os, OsFamily::Other);
        assert_eq!(b.device, DeviceClass::Unknown);
    }

    #[test]
    fn whitespace_only_is_unknown() {
        let b = bucket_user_agent("   ");
        assert_eq!(b.device, DeviceClass::Unknown);
    }

    #[test]
    fn garbage_ua_is_other_not_a_panic() {
        let b = bucket_user_agent("total garbage \0 \u{1F600} not a real UA at all");
        assert_eq!(b.browser, BrowserFamily::Other);
    }
}
