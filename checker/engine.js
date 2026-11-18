// Silver Shield scam checker engine.
// Works in the browser (window.SilverShield) and in Node (require).
// Two signals:
//   1. Red-flag rules: explainable patterns in English, Spanish and Chinese.
//   2. A naive Bayes word model trained on the UCI SMS Spam Collection (English only).
// Three verdicts, never "safe": likely_scam, cannot_tell, no_red_flags.
// Every link is checked: is it a real web address, and does it use scam tricks (look-alike names, short links, ...)?
// Each result also carries `report`, the team format in scam-checker-output.md.
(function (root) {
  "use strict";

  // Each flag: patterns (case-insensitive regex sources), weight, explanations per language.
  var FLAGS = [
    {
      id: "money_move",
      weight: 3,
      patterns: [
        "gift ?cards?", "wire (the )?(money|funds|transfer)", "bitcoin", "crypto(currency)?",
        "zelle", "venmo", "cash ?app", "western union", "moneygram", "safe account",
        "protect your (money|funds|savings)", "move your (money|funds|savings)",
        "tarjetas? de regalo", "transferencia", "cuenta segura", "giro",
        "转账", "汇款", "礼品卡", "安全账户", "比特币", "虚拟货币"
      ],
      text: {
        en: "It asks you to send or move money, or to pay with gift cards, crypto or a payment app. Banks and government agencies never ask for that.",
        es: "Le pide enviar o mover dinero, o pagar con tarjetas de regalo, criptomonedas o una aplicación de pagos. Los bancos y el gobierno nunca piden eso.",
        zh: "它要求您转账、汇款，或用礼品卡、加密货币、支付应用付款。银行和政府机构从不会这样要求。"
      }
    },
    {
      id: "secrets",
      weight: 3,
      patterns: [
        "password", "\\bpin\\b", "\\botp\\b", "one[- ]time password", "social security( number)?", "\\bssn\\b", "one[- ]time (pass)?code",
        "verification code", "security code", "verify your (account|identity|details|information)",
        "confirm your (account|identity|details|information|card)", "update your (account|billing|payment)",
        "bank (details|account number)", "card (number|details)",
        "contraseña", "verifi(que|car) su (cuenta|identidad)", "confirm(e|ar) su (cuenta|identidad|tarjeta)",
        "datos bancarios", "número de (tarjeta|seguro social)", "código de (verificación|seguridad)",
        "密码", "验证码", "身份证", "银行卡号", "核实身份", "核实您的", "账户信息"
      ],
      text: {
        en: "It asks for a password, code, card number or identity details. A real company will not ask you to send these by message.",
        es: "Le pide una contraseña, un código, el número de tarjeta o datos personales. Una empresa real no le pide esto por mensaje.",
        zh: "它索要密码、验证码、卡号或身份信息。正规机构不会通过短信索要这些信息。"
      }
    },
    {
      id: "urgency",
      weight: 1.5,
      patterns: [
        "urgent", "immediately", "right away", "act now", "within (24|48|12) ?(hours|hrs|h)\\b", "today only",
        "final (notice|warning|reminder)", "(account|card|service) (has been |will be |is )?(suspended|locked|blocked|frozen|disabled|closed)",
        "will be (suspended|locked|closed|cancelled|canceled)", "(blocked|locked|suspended|closed|frozen|deactivated) in \\d+ ?(hours?|hrs?|minutes?|mins?)", "within \\d+ ?(hours?|hrs?)\\b", "expires? (today|soon|in)", "last chance", "avoid (penalt|late fee|suspension|legal)",
        "urgente", "inmediatamente", "de inmediato", "suspendid[ao]", "bloquead[ao]", "último aviso", "en (24|48) horas",
        "紧急", "立即", "马上", "冻结", "暂停", "停用", "最后通知", "24小时", "逾期"
      ],
      text: {
        en: "It pushes you to act fast or says something will be blocked. Scammers rush people so they do not stop and check.",
        es: "Le presiona a actuar rápido o dice que algo será bloqueado. Los estafadores apuran para que usted no se detenga a verificar.",
        zh: "它催促您马上行动，或声称账户将被冻结。骗子制造紧迫感，让人来不及核实。"
      }
    },
    {
      id: "prize",
      weight: 2,
      patterns: [
        "you('ve| have)? (won|been selected)", "\\bwinner\\b", "\\bprize\\b", "\\bclaim\\b", "\\bcongrat", "guaranteed",
        "free (gift|entry|cash|money|iphone|phone|vacation|trip)", "cash (prize|reward)", "\\breward\\b", "\\bawarded\\b",
        "ha ganado", "ganador", "premio", "gratis", "reclam(e|ar)", "felicidades",
        "中奖", "恭喜", "奖品", "奖金", "免费领取", "领取"
      ],
      text: {
        en: "It says you won something or offers free money. If you did not enter, you did not win.",
        es: "Dice que usted ganó algo u ofrece dinero gratis. Si no participó, no ganó.",
        zh: "它声称您中奖了或可以免费领钱。没参加过的活动，就不可能中奖。"
      }
    },
    {
      id: "delivery_toll",
      weight: 2,
      patterns: [
        "unpaid toll", "toll (balance|charge|violation|notice)", "(package|parcel|shipment|delivery) (could not|cannot|can't|was not|is on hold|on hold|held|failed|pending)",
        "redeliver", "re-deliver", "delivery fee", "customs fee", "shipping fee", "address (is )?incomplete",
        "peaje", "paquete", "entrega fallida", "tarifa de envío",
        "包裹", "快递.*(失败|异常|无法)", "关税", "过路费", "派送失败"
      ],
      text: {
        en: "It claims an unpaid toll or a stuck package and wants a small payment. These fake notices are one of the most common texts right now.",
        es: "Dice que hay un peaje sin pagar o un paquete retenido y pide un pago pequeño. Estos avisos falsos son de los mensajes más comunes hoy.",
        zh: "它声称有未付过路费或包裹滞留，要求支付小额费用。这类假通知是目前最常见的诈骗短信之一。"
      }
    },
    {
      id: "family_secret",
      weight: 2.5,
      patterns: [
        "(hi|hey) (mom|mum|dad|grandma|grandpa)", "(this is|it's) my new number", "lost my phone", "broke my phone",
        "don'?t tell (anyone|mom|dad|your)", "keep (this|it) (between us|secret|quiet)", "in (jail|trouble|the hospital)",
        "mamá|papá|abuel[ao]", "mi nuevo número", "perdí mi (teléfono|celular)", "no (le )?digas a nadie",
        "我换号了", "新号码", "不要告诉", "保密", "出事了"
      ],
      text: {
        en: "It claims to be a family member with a new number or an emergency, or asks you to keep a secret. Call the person on the number you already have.",
        es: "Dice ser un familiar con número nuevo o en una emergencia, o le pide guardar un secreto. Llame a esa persona al número que usted ya tiene.",
        zh: "它自称是换了号码或遇到紧急情况的家人，或要求您保密。请拨打您原来保存的号码核实。"
      }
    },
    {
      id: "job_invest",
      weight: 2,
      patterns: [
        "work from home", "earn \\$?\\d+", "\\$\\d+ (a|per) (day|hour|week)", "per day", "guaranteed (return|profit|income)",
        "investment opportunity", "(crypto|forex) trading", "easy money", "part[- ]time (job|position)",
        "trabajo desde casa", "gane \\$?\\d+", "ganancias garantizadas", "oportunidad de inversión",
        "兼职", "日赚", "刷单", "高回报", "稳赚", "投资理财", "带你赚钱"
      ],
      text: {
        en: "It offers easy pay or guaranteed investment returns. Real jobs do not recruit by random text, and no investment is guaranteed.",
        es: "Ofrece dinero fácil o ganancias garantizadas. Los trabajos reales no se ofrecen por mensajes al azar y ninguna inversión es segura.",
        zh: "它承诺轻松赚钱或保证投资回报。正规工作不会随机发短信招人，任何投资都没有保证。"
      }
    },
    {
      id: "impersonation",
      weight: 1,
      patterns: [
        "\\birs\\b", "\\busps\\b", "\\bfedex\\b", "\\bups\\b", "\\bdhl\\b", "amazon", "paypal", "apple ?id", "netflix",
        "wells fargo", "chase", "bank of america", "\\bsbi\\b", "state bank of india", "\\bhdfc\\b", "\\bicici\\b", "fraud (team|department|prevention)", "\\bbank\\b", "social security administration", "medicare",
        "\\bdmv\\b", "fastrak", "e-?zpass", "police", "sheriff", "\\bcourt\\b", "microsoft", "geek squad",
        "banco", "policía", "seguro social", "hacienda",
        "银行", "公安", "警察", "海关", "大使馆", "税务局", "客服"
      ],
      text: {
        en: "It names a bank, agency or well-known company. Scammers borrow trusted names; contact that company yourself using its official website or the number on your card.",
        es: "Menciona un banco, una agencia o una empresa conocida. Los estafadores usan nombres de confianza; contacte a la empresa usted mismo por su sitio oficial o el número de su tarjeta.",
        zh: "它冒用了银行、政府机构或知名公司的名义。请自己通过官网或卡背面的电话联系该机构核实。"
      }
    },
    {
      id: "reply_call",
      weight: 1.5,
      patterns: [
        "\\b(txt|text|reply|send)\\b [a-z0-9]{2,12} to \\d{4,6}", "\\bcall (now )?0?9\\d{8,}", "\\b0?8\\d{3} ?\\d{3} ?\\d{3,4}\\b",
        "\\b\\d{5}\\b.*\\b(stop|txt)\\b", "\\bpremium (rate|number)", "\\b\\d+p ?(/|per) ?(min|msg|txt)",
        "responda .* al \\d{4,6}", "回复.*\\d{4,6}"
      ],
      text: {
        en: "It asks you to text a code word or call a number. Replying can sign you up for paid messages or confirm your number is active.",
        es: "Le pide responder con una palabra o llamar a un número. Responder puede suscribirle a mensajes pagados o confirmar que su número está activo.",
        zh: "它要求您回复关键词或拨打某个号码。回复可能会订阅付费短信，或让骗子确认您的号码有效。"
      }
    }
  ];

  var NB_FLAG_TEXT = {
    en: "Its wording closely matches known spam and scam texts.",
    es: "Su redacción se parece mucho a mensajes de spam y estafa conocidos.",
    zh: "它的措辞与已知的垃圾短信和诈骗短信非常相似。"
  };

  // ---------------------------------------------------------------------------
  // Link checker. Finds every web address in the text, checks that it is a real,
  // well-formed address, and looks for the tricks scam links use.
  // ---------------------------------------------------------------------------
  var TLD_LIST = (typeof module !== "undefined" && module.exports) ? require("./tlds.js") : root.SilverShieldTLDs;
  var TLDS = {};
  (TLD_LIST || "").split(" ").forEach(function (t) { if (t) TLDS[t] = true; });

  // Scheme or www links: everything up to whitespace. Bare links (fastrak-pay.xyz): letters, digits,
  // hyphens and dots, plus Latin, Greek and Cyrillic letters so look-alike spellings are caught.
  var L = "a-z0-9À-ɏͰ-ϿЀ-ӿ";
  var LINK_RE = new RegExp(
    "(?:https?:\\/\\/|www\\.)[^\\s<>\"'“”　]+" +
    "|(?:[" + L + "](?:[" + L + "-]*[" + L + "])?\\.)+[a-zЀ-ӿ][" + L + "-]*(?:\\/[^\\s<>\"'“”　]*)?",
    "gi");
  var TRAILING = /[.,;:!?)\]}>'"’”。，！？；：）]+$/;

  // Two-part endings where the registered name sits one level further left (example.co.uk).
  var MULTI_SUFFIX = { "co.uk": 1, "org.uk": 1, "ac.uk": 1, "gov.uk": 1, "co.in": 1, "org.in": 1, "net.in": 1, "gov.in": 1,
    "com.au": 1, "net.au": 1, "org.au": 1, "gov.au": 1, "co.nz": 1, "com.br": 1, "com.mx": 1, "gob.mx": 1, "com.cn": 1,
    "gov.cn": 1, "com.hk": 1, "co.jp": 1, "co.za": 1, "com.sg": 1, "com.tw": 1, "com.es": 1 };
  // Endings common enough in real links to accept without http:// or www. in front.
  var BARE_TLDS = {};
  ("com net org gov edu mil info biz io co ly cc app dev ai tv uk ca au de fr es mx br cn ru jp kr sg hk tw nz eu ch nl se ie za ph pk ng")
    .split(" ").forEach(function (t) { BARE_TLDS[t] = true; });
  // Real web endings that are far more often file names when written without http:// or www.
  var FILE_ENDINGS = { py: 1, pm: 1, pl: 1, sh: 1, js: 1, md: 1, rs: 1, so: 1, zip: 1, mov: 1, cat: 1, tar: 1, doc: 1, exe: 1, pdf: 1, txt: 1 };
  var SHORTENER_DOMAINS = { "bit.ly": 1, "tinyurl.com": 1, "t.co": 1, "goo.gl": 1, "is.gd": 1, "ow.ly": 1, "rb.gy": 1,
    "cutt.ly": 1, "shorturl.at": 1, "tiny.cc": 1, "t.ly": 1, "s.id": 1, "v.gd": 1, "bl.ink": 1, "short.io": 1,
    "rebrand.ly": 1, "buff.ly": 1, "lnkd.in": 1, "qrco.de": 1, "u.to": 1, "clck.ru": 1, "dwz.cn": 1, "url.cn": 1 };
  // Endings that are cheap to register and common in scam texts, rare for banks, agencies and shops.
  var RISKY_TLDS = { top: 1, xyz: 1, click: 1, link: 1, vip: 1, shop: 1, online: 1, site: 1, live: 1, cc: 1, info: 1,
    biz: 1, cn: 1, icu: 1, buzz: 1, cyou: 1, sbs: 1, cfd: 1, rest: 1, bond: 1, autos: 1, lol: 1, quest: 1, mom: 1,
    work: 1, support: 1, win: 1, loan: 1, gq: 1, tk: 1, ml: 1, cf: 1, ga: 1, zip: 1, mov: 1 };

  // Brands scammers borrow, the words that name them in a message, and the web addresses they really own.
  // A link that uses the brand's name but is not on this list is a look-alike.
  var BRANDS = [
    { name: "USPS", tokens: ["usps"], mention: "\\busps\\b|postal service", domains: ["usps.com", "usps.gov"] },
    { name: "FedEx", tokens: ["fedex"], mention: "\\bfedex\\b", domains: ["fedex.com"] },
    { name: "UPS", tokens: ["ups"], mention: "\\bups\\b", domains: ["ups.com"] },
    { name: "DHL", tokens: ["dhl"], mention: "\\bdhl\\b", domains: ["dhl.com", "dhl.de"] },
    { name: "Amazon", tokens: ["amazon", "amzn"], mention: "amazon|\\bamzn\\b", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.ca", "amazon.com.mx", "amazon.es", "amazon.cn", "amzn.to", "amazonaws.com"] },
    { name: "PayPal", tokens: ["paypal"], mention: "paypal", domains: ["paypal.com", "paypal.me"] },
    { name: "Apple", tokens: ["apple", "icloud", "appleid"], mention: "\\bapple\\b|icloud|apple ?id", domains: ["apple.com", "icloud.com"] },
    { name: "Netflix", tokens: ["netflix"], mention: "netflix", domains: ["netflix.com"] },
    { name: "Chase", tokens: ["chase"], mention: "\\bchase\\b", domains: ["chase.com"] },
    { name: "Wells Fargo", tokens: ["wellsfargo"], mention: "wells ?fargo", domains: ["wellsfargo.com"] },
    { name: "Bank of America", tokens: ["bankofamerica", "bofa"], mention: "bank of america|\\bbofa\\b", domains: ["bankofamerica.com"] },
    { name: "SBI", tokens: ["sbi", "onlinesbi", "statebankofindia"], mention: "\\bsbi\\b|state bank of india", domains: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"] },
    { name: "HDFC Bank", tokens: ["hdfc", "hdfcbank"], mention: "\\bhdfc\\b", domains: ["hdfcbank.com", "hdfc.bank.in"] },
    { name: "ICICI Bank", tokens: ["icici", "icicibank"], mention: "\\bicici\\b", domains: ["icicibank.com", "icici.bank.in"] },
    { name: "IRS", tokens: ["irs"], mention: "\\birs\\b", domains: ["irs.gov"] },
    { name: "Social Security", tokens: ["ssa"], mention: "social security|seguro social", domains: ["ssa.gov"] },
    { name: "Medicare", tokens: ["medicare"], mention: "medicare", domains: ["medicare.gov"] },
    { name: "FasTrak", tokens: ["fastrak"], mention: "fas ?trak", domains: ["bayareafastrak.org", "thetollroads.com"] },
    { name: "E-ZPass", tokens: ["ezpass"], mention: "e-?z ?pass", domains: ["e-zpassny.com", "ezpassnj.com", "ezpassva.com", "ezpassmd.com", "ezpassde.com", "ezpassma.com", "ezpass.com"] },
    { name: "Microsoft", tokens: ["microsoft"], mention: "microsoft", domains: ["microsoft.com", "live.com", "outlook.com"] },
    { name: "WhatsApp", tokens: ["whatsapp"], mention: "whatsapp", domains: ["whatsapp.com", "wa.me"] }
  ];
  BRANDS.forEach(function (b) { b.mentionRe = new RegExp(b.mention, "i"); });

  // Problems a link can have. "strong" problems make it a bad link; weak ones are reported but add little.
  var LINK_PROBLEMS = {
    invalid: { strong: true, text: {
      en: "“{url}” is not a real, working web address ({why}). Companies send correct links; a broken or made-up address is a warning sign.",
      es: "“{url}” no es una dirección web real y válida ({why}). Las empresas envían enlaces correctos; una dirección rota o inventada es una señal de alerta.",
      zh: "“{url}”不是有效的真实网址（{why}）。正规机构发送的链接是正确的；无效或捏造的网址是危险信号。" } },
    ip_address: { strong: true, text: {
      en: "The link uses a string of numbers ({host}) instead of a company name. Real companies do not do that.",
      es: "El enlace usa una serie de números ({host}) en lugar del nombre de una empresa. Las empresas reales no hacen eso.",
      zh: "该链接使用一串数字（{host}）而不是公司名称。正规公司不会这样做。" } },
    shortener: { strong: true, text: {
      en: "The link is shortened ({domain}), which hides where it really goes.",
      es: "El enlace está acortado ({domain}), lo que oculta a dónde lleva realmente.",
      zh: "这是短链接（{domain}），会隐藏真实的目标网址。" } },
    risky_tld: { strong: true, text: {
      en: "The address ends in “.{tld}”, an ending scammers use a lot and banks, agencies and big companies rarely use.",
      es: "La dirección termina en “.{tld}”, una terminación muy usada por estafadores y casi nunca por bancos, agencias o grandes empresas.",
      zh: "该网址以“.{tld}”结尾，骗子经常使用这种后缀，而银行、政府和大公司很少使用。" } },
    lookalike_letters: { strong: true, text: {
      en: "The address uses look-alike letters from another alphabet to imitate a real name ({host}).",
      es: "La dirección usa letras parecidas de otro alfabeto para imitar un nombre real ({host}).",
      zh: "该网址使用其他文字中外形相似的字母来冒充真实名称（{host}）。" } },
    at_sign: { strong: true, text: {
      en: "The address hides its real destination after an “@” sign. It actually goes to {host}.",
      es: "La dirección oculta su destino real después de una “@”. En realidad lleva a {host}.",
      zh: "该网址把真实目标藏在“@”符号之后，实际会打开 {host}。" } },
    brand_lookalike: { strong: true, text: {
      en: "The address uses the name “{brand}”, but it is not {brand}'s website. It belongs to {domain}.",
      es: "La dirección usa el nombre “{brand}”, pero no es el sitio de {brand}. Pertenece a {domain}.",
      zh: "该网址使用了“{brand}”的名称，但并不是{brand}的官网，它实际属于 {domain}。" } },
    brand_mismatch: { strong: true, text: {
      en: "The message says it is from {brand}, but the link goes to {domain}, which is not {brand}'s website.",
      es: "El mensaje dice ser de {brand}, pero el enlace lleva a {domain}, que no es el sitio de {brand}.",
      zh: "信息自称来自{brand}，但链接指向 {domain}，这不是{brand}的官网。" } },
    not_secure: { strong: false, text: {
      en: "The link does not use a secure connection (it starts with http, not https).",
      es: "El enlace no usa una conexión segura (empieza con http, no https).",
      zh: "该链接没有使用安全连接（以 http 而不是 https 开头）。" } }
  };
  var INVALID_WHY = {
    malformed: { en: "it is not written like a web address", es: "no está escrita como una dirección web", zh: "格式不像网址" },
    no_dot: { en: "it has no web ending such as .com", es: "no tiene terminación como .com", zh: "缺少 .com 之类的后缀" },
    bad_label: { en: "it contains characters a web address cannot have", es: "contiene caracteres que una dirección web no puede tener", zh: "含有网址中不允许的字符" },
    unknown_tld: { en: "“.{tld}” is not a real web ending", es: "“.{tld}” no es una terminación web real", zh: "“.{tld}”不是真实存在的网址后缀" }
  };
  var LINK_OK_TEXT = {
    en: "It contains a link. Do not tap links in unexpected messages; type the company's address yourself.",
    es: "Contiene un enlace. No toque enlaces en mensajes inesperados; escriba usted mismo la dirección de la empresa.",
    zh: "它包含链接。不要点击陌生短信中的链接，请自己输入官方网址。"
  };
  var LINK_OFFICIAL_TEXT = {
    en: "The link goes to {domain}, which is {brand}'s real website. Even so, open the app or type the address yourself instead of tapping.",
    es: "El enlace lleva a {domain}, el sitio real de {brand}. Aun así, abra la aplicación o escriba la dirección usted mismo en lugar de tocar el enlace.",
    zh: "该链接指向 {domain}，是{brand}的真实官网。即便如此，也请自己打开应用或手动输入网址，而不要直接点击。"
  };

  function fill(tpl, vars) {
    return tpl.replace(/\{(\w+)\}/g, function (_, k) { return vars[k] !== undefined ? vars[k] : ""; });
  }

  function registrableDomain(host) {
    var parts = host.split(".");
    if (parts.length <= 2) return host;
    var last2 = parts.slice(-2).join(".");
    return MULTI_SUFFIX[last2] ? parts.slice(-3).join(".") : last2;
  }

  // Undo common character swaps scammers use: paypa1 -> paypal, amaz0n -> amazon, rn -> m.
  function unswap(s) {
    return s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/rn/g, "m").replace(/vv/g, "w");
  }
  function oneEditAway(a, b) {
    if (a === b || Math.abs(a.length - b.length) > 1) return false;
    var i = 0, j = 0, edits = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++edits > 1) return false;
      if (a.length > b.length) i++; else if (b.length > a.length) j++; else { i++; j++; }
    }
    return edits + (a.length - i) + (b.length - j) <= 1;
  }
  function isOfficial(brand, domain) {
    return brand.domains.some(function (d) { return domain === d || domain.slice(-(d.length + 1)) === "." + d; });
  }
  // Does this host borrow a brand's name? Checks each hyphen-separated piece of each label.
  function brandInHost(host, domain) {
    var labels = host.split(".").slice(0, -1);
    var regLabel = domain.split(".")[0];
    for (var b = 0; b < BRANDS.length; b++) {
      var brand = BRANDS[b];
      if (isOfficial(brand, host)) continue;
      for (var t = 0; t < brand.tokens.length; t++) {
        var tok = brand.tokens[t];
        for (var l = 0; l < labels.length; l++) {
          var pieces = labels[l].split("-");
          for (var p = 0; p < pieces.length; p++) {
            var piece = pieces[p];
            if (piece === tok || (tok.length >= 4 && piece.indexOf(tok) === 0 && piece.length > tok.length)) return brand;
            if (labels[l] === regLabel && piece !== tok && tok.length >= 5 && (unswap(piece) === tok || (tok.length >= 6 && oneEditAway(piece, tok)))) return brand;
          }
        }
      }
    }
    return null;
  }

  function findLinks(text) {
    var out = [], m;
    LINK_RE.lastIndex = 0;
    while ((m = LINK_RE.exec(text))) {
      var raw = m[0].replace(TRAILING, "");
      var before = text.charAt(m.index - 1), after = text.charAt(m.index + m[0].length);
      if (before === "@" || after === "@") continue; // part of an email address
      var hasScheme = /^(https?:\/\/|www\.)/i.test(raw);
      if (!hasScheme) {
        // A bare "word.word" only counts as a link if it ends in a real web ending and is not "a.m." or "U.S.".
        // Also skip file names (script.py) and run-together sentences ("too.You").
        var hostPart = raw.split("/")[0];
        var labels = hostPart.split(".");
        var tldRaw = labels[labels.length - 1], tld = tldRaw.toLowerCase();
        var hasPath = raw.indexOf("/") !== -1;
        if (!TLDS[tld] || labels[labels.length - 2].length < 2) continue;
        // Many endings are also everyday words (.call, .love, .my, .in), so a bare "word.word" needs a
        // common link ending, or a path after it, to count as a link.
        if (!(BARE_TLDS[tld] || RISKY_TLDS[tld]) && !hasPath) continue;
        if (FILE_ENDINGS[tld] && !hasPath) continue;
        if (/^[A-Z][a-z]+$/.test(tldRaw)) continue;
      }
      out.push(raw);
    }
    return out;
  }

  function checkLink(raw, mentioned) {
    var res = { url: raw, valid: true, host: null, domain: null, problems: [], official: null };
    var href = /^https?:\/\//i.test(raw) ? raw : "http://" + raw;
    var u;
    try { u = new URL(href); } catch (e) { u = null; }
    if (!u || !u.hostname) {
      res.valid = false;
      res.problems.push({ id: "invalid", why: "malformed" });
      return res;
    }
    var host = u.hostname.toLowerCase().replace(/\.$/, "");
    res.host = host;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.charAt(0) === "[") {
      res.domain = host;
      res.problems.push({ id: "ip_address" });
    } else {
      var labels = host.split(".");
      var tld = labels[labels.length - 1];
      if (labels.length < 2) { res.valid = false; res.problems.push({ id: "invalid", why: "no_dot" }); }
      else if (!labels.every(function (l) { return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l); })) {
        res.valid = false; res.problems.push({ id: "invalid", why: "bad_label" });
      } else if (!TLDS[tld]) { res.valid = false; res.problems.push({ id: "invalid", why: "unknown_tld", tld: tld }); }
      res.domain = registrableDomain(host);
      // Keep the address as typed for explanations, so tricks like "netfIix" or Cyrillic letters stay visible.
      var hostInText = raw.replace(/^https?:\/\//i, "").split(/[\/?#]/)[0].split("@").pop().split(":")[0].replace(/\.$/, "");
      if (hostInText.split(".").length === labels.length) { res.shownHost = hostInText; res.shownDomain = registrableDomain(hostInText); }
      if (res.valid) {
        if (host.indexOf("xn--") !== -1 || /[^\x00-\x7f]/.test(hostInText)) res.problems.push({ id: "lookalike_letters" });
        if (SHORTENER_DOMAINS[res.domain]) res.problems.push({ id: "shortener" });
        if (RISKY_TLDS[tld]) res.problems.push({ id: "risky_tld", tld: tld });
        var officialFor = null;
        BRANDS.forEach(function (b) { if (!officialFor && isOfficial(b, host)) officialFor = b; });
        if (officialFor) res.official = officialFor.name;
        var borrowed = officialFor ? null : brandInHost(host, res.domain);
        if (borrowed) res.problems.push({ id: "brand_lookalike", brand: borrowed.name });
        if (!officialFor && !SHORTENER_DOMAINS[res.domain]) {
          var claimed = mentioned.filter(function (b) { return !borrowed || b.name !== borrowed.name; })[0];
          if (claimed) res.problems.push({ id: "brand_mismatch", brand: claimed.name });
        }
      }
    }
    if (u.username || u.password) res.problems.push({ id: "at_sign" });
    if (/^http:\/\//i.test(raw)) res.problems.push({ id: "not_secure" });
    return res;
  }

  function explainLink(l, lang) {
    var vars = { url: l.url, host: l.shownHost || l.host || l.url, domain: l.shownDomain || l.domain || l.host || l.url };
    var lines = l.problems.map(function (p) {
      var v = Object.assign({}, vars, { brand: p.brand || "", tld: p.tld || "" });
      if (p.why) v.why = fill(INVALID_WHY[p.why][lang], v);
      return fill(LINK_PROBLEMS[p.id].text[lang], v);
    });
    if (!lines.length && l.official) lines.push(fill(LINK_OFFICIAL_TEXT[lang], { domain: vars.domain, brand: l.official }));
    return lines;
  }

  function analyzeLinks(text, lang) {
    // Only a brand named near the start counts as "the message says it is from X" ("USPS: ...", "Hi, this is Chase ...").
    var opening = text.slice(0, 60);
    var mentioned = BRANDS.filter(function (b) { return b.mentionRe.test(opening); });
    var seen = {};
    return findLinks(text).filter(function (u) { return seen[u] ? false : (seen[u] = true); }).map(function (raw) {
      var l = checkLink(raw, mentioned);
      l.suspicious = l.problems.some(function (p) { return LINK_PROBLEMS[p.id].strong; });
      l.status = !l.valid ? "not_a_valid_address" : l.suspicious ? "suspicious" : l.official ? "official_domain" : "no_problems_found";
      l.explanations = explainLink(l, lang);
      l.problems = l.problems.map(function (p) { return p.id; });
      return l;
    });
  }

  var VERDICT_TEXT = {
    likely_scam: { en: "Likely scam", es: "Probable estafa", zh: "很可能是诈骗" },
    cannot_tell: { en: "Cannot tell: be careful", es: "No se puede saber: tenga cuidado", zh: "无法判断：请保持警惕" },
    no_red_flags: { en: "No red flags found", es: "No se encontraron señales de alerta", zh: "未发现危险信号" }
  };

  var CAVEAT_TEXT = {
    en: "This does not mean the message is safe. It only means this checker found none of the warning signs it knows.",
    es: "Esto no significa que el mensaje sea seguro. Solo significa que este verificador no encontró las señales que conoce.",
    zh: "这并不代表该信息是安全的，只表示本工具没有发现它已知的危险信号。"
  };

  var NEXT_STEPS = {
    en: [
      "Do not reply, tap links, or call numbers in the message.",
      "Contact the company yourself: use the number on the back of your card or type its official website.",
      "If it claims to be family, call them on the number you already have.",
      "Report it at reportfraud.ftc.gov, and forward scam texts to 7726 (SPAM).",
      "If you already paid or shared a code, call your bank right away."
    ],
    es: [
      "No responda, no toque enlaces ni llame a números del mensaje.",
      "Contacte a la empresa usted mismo: use el número al reverso de su tarjeta o escriba su sitio oficial.",
      "Si dice ser un familiar, llámele al número que usted ya tiene.",
      "Repórtelo en reportfraud.ftc.gov y reenvíe los mensajes de estafa al 7726 (SPAM).",
      "Si ya pagó o compartió un código, llame a su banco de inmediato."
    ],
    zh: [
      "不要回复、点击链接或拨打短信中的号码。",
      "自己联系该机构：拨打银行卡背面的电话，或手动输入官方网址。",
      "如果对方自称家人，请用您原来保存的号码打给他们。",
      "可在 reportfraud.ftc.gov 举报，并将诈骗短信转发到 7726 (SPAM)。",
      "如果已经付款或泄露验证码，请立即致电您的银行。"
    ]
  };

  var compiled = FLAGS.map(function (f) {
    return { flag: f, re: new RegExp("(" + f.patterns.join("|") + ")", "i") };
  });

  function detectLanguage(text) {
    var cjk = (text.match(/[一-鿿]/g) || []).length;
    if (cjk >= 2) return "zh";
    var t = " " + text.toLowerCase() + " ";
    if (/[ñ¿¡]/.test(t)) return "es";
    var es = (t.match(/ (el|la|los|las|usted|su|sus|para|por|que|cuenta|mensaje|hola|gracias|está|tiene|aquí) /g) || []).length;
    var en = (t.match(/ (the|you|your|to|and|is|are|for|this|have|please|now) /g) || []).length;
    return es > en ? "es" : "en";
  }

  function tokenize(text) {
    return (text.toLowerCase().match(/[a-z0-9£$]+(?:'[a-z]+)?/g) || []);
  }

  // model: { prior: logit, w: { token: logRatio }, unk: logRatio }
  function nbLogit(text, model) {
    if (!model) return null;
    var toks = tokenize(text);
    if (!toks.length) return null;
    var s = model.prior;
    for (var i = 0; i < toks.length; i++) {
      var w = model.w[toks[i]];
      if (w !== undefined) s += w;
    }
    return s;
  }

  function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

  function check(text, opts) {
    opts = opts || {};
    var model = opts.model === undefined ? root.SilverShieldModel : opts.model;
    var useRules = opts.rules !== false;
    var lang = opts.lang || detectLanguage(text);
    var flags = [];
    var score = 0;
    var links = [];

    if (useRules) {
      compiled.forEach(function (c) {
        var m = text.match(c.re);
        if (m) {
          flags.push({ id: c.flag.id, weight: c.flag.weight, match: m[0], text: c.flag.text });
          score += c.flag.weight;
        }
      });

      links = analyzeLinks(text, lang);
      if (links.length) {
        var bad = links.filter(function (l) { return l.suspicious; });
        if (bad.length) {
          var strongText = bad[0].explanations.filter(function (_, i) { return LINK_PROBLEMS[bad[0].problems[i]].strong; });
          flags.push({ id: "bad_link", weight: 2.5, match: bad[0].url, explanation: strongText.join(" ") });
          score += 2.5;
        } else {
          var off = links.filter(function (l) { return l.official; })[0];
          var okText = off && links.length === 1 ? fill(LINK_OFFICIAL_TEXT[lang], { domain: off.domain, brand: off.official }) : LINK_OK_TEXT[lang];
          flags.push({ id: "link", weight: 1, match: links[0].url, explanation: okText });
          score += 1;
        }
      }
    }

    // The word model only knows English, so ignore it for other languages.
    var logit = lang === "en" ? nbLogit(text, model) : null;
    var p = logit === null ? null : sigmoid(logit);
    if (p !== null && p >= 0.9 && useRules) {
      flags.push({ id: "wording", weight: 0, match: "", text: NB_FLAG_TEXT });
    }

    var verdict;
    if (!useRules) {
      verdict = p === null ? "cannot_tell" : p >= 0.5 ? "likely_scam" : p < 0.2 ? "no_red_flags" : "cannot_tell";
    } else if (score >= 3 || (score >= 1 && p !== null && p >= 0.5) || (p !== null && p >= 0.95)) {
      verdict = "likely_scam";
    } else if (score === 0 && (p === null ? true : p < 0.2)) {
      verdict = "no_red_flags";
    } else {
      verdict = "cannot_tell";
    }

    var out = {
      verdict: verdict,
      verdictText: VERDICT_TEXT[verdict][lang],
      lang: lang,
      score: score,
      modelProbability: p,
      flags: flags.map(function (f) { return { id: f.id, match: f.match, explanation: f.explanation || f.text[lang] }; }),
      links: links,
      caveat: verdict === "no_red_flags" ? CAVEAT_TEXT[lang] : null,
      nextSteps: NEXT_STEPS[lang]
    };
    out.report = buildReport(text, out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // Team report format (scam-checker-output.md): five signals, scam stages, a type
  // guess, risk, confidence, a recommended action and what still needs checking.
  // ---------------------------------------------------------------------------
  var FAMILY_CLAIM = /(hi|hey|hello) (mom|mum|dad|grandma|grandpa|nana)|(this is|it's) my new number|lost my phone|broke my phone|hola (mamá|papá|abuel[ao])|mi nuevo número|perdí mi (teléfono|celular)|我换号了|新号码|妈，我|爸，我/i;
  var PAY_ASK = /\bpay\b|payment|\bfee\b|\bsend (me )?\$|pagar|pagando|pago|tarifa|支付|付款|缴费|转账|汇款/i;
  var SECRECY = /don'?t tell|do not tell|keep (this|it) (between us|secret|quiet|confidential|private)|no (le |se lo )?digas a nadie|no le (diga|cuente)|no se lo digas|不要告诉|别告诉|保密/i;
  var GOV = /\birs\b|social security|medicare|\bdmv\b|police|sheriff|\bcourt\b|policía|seguro social|hacienda|公安|警察|海关|大使馆|税务局/i;
  var BANKISH = /bank|banco|chase|wells fargo|\bsbi\b|\bhdfc\b|\bicici\b|paypal|fraud (team|department)|银行/i;

  function sig(match) { return match ? { present: true, evidence: match } : { present: false, evidence: null }; }
  function firstMatch(re, text) { var m = text.match(re); return m ? m[0] : null; }

  function buildReport(text, r) {
    var byId = {};
    r.flags.forEach(function (f) { byId[f.id] = f; });
    var lookalike = r.links.filter(function (l) { return l.problems.indexOf("brand_lookalike") !== -1 || l.problems.indexOf("brand_mismatch") !== -1; })[0];
    var family = firstMatch(FAMILY_CLAIM, text);

    var payMatch = byId.money_move ? byId.money_move.match : firstMatch(PAY_ASK, text);
    var signals = {
      impersonation: sig(byId.impersonation ? byId.impersonation.match : family || (lookalike ? lookalike.url : null)),
      urgency: sig(byId.urgency ? byId.urgency.match : null),
      money_ask: sig(payMatch),
      credential_ask: sig(byId.secrets ? byId.secrets.match : null),
      secrecy: sig(firstMatch(SECRECY, text))
    };

    var stage = [];
    if (signals.impersonation.present || byId.prize || byId.job_invest) stage.push("trust");
    if (signals.urgency.present) stage.push("urgency");
    if (signals.money_ask.present || signals.credential_ask.present || r.links.length || byId.reply_call) stage.push("ask");

    var imp = byId.impersonation ? byId.impersonation.match : "";
    var type =
      family ? "family_emergency" :
      GOV.test(imp) ? "government_impersonation" :
      byId.delivery_toll ? "toll_or_delivery" :
      byId.prize ? "prize_or_lottery" :
      byId.job_invest ? "job_or_investment" :
      byId.money_move && !imp ? "payment_request" :
      BANKISH.test(imp) || (imp && byId.secrets) ? "bank_impersonation" :
      imp || lookalike ? "company_impersonation" :
      byId.bad_link ? "phishing_link" :
      byId.reply_call ? "premium_text_or_call" :
      r.verdict === "no_red_flags" ? "none" : "unknown";

    // Heuristic, not calibrated: grows with the red-flag score and the word model's probability.
    var conf;
    if (r.verdict === "likely_scam") conf = Math.max(1 - Math.exp(-r.score / 3), r.modelProbability || 0, 0.6);
    else if (r.verdict === "cannot_tell") conf = 0.5;
    else conf = r.modelProbability === null ? 0.6 : 1 - r.modelProbability;
    conf = Math.round(Math.min(conf, 0.95) * 100) / 100;

    var action =
      r.verdict === "no_red_flags" ? "no_red_flags_found_stay_careful" :
      r.verdict === "cannot_tell" ? "verify_via_official_channel_before_acting" :
      type === "family_emergency" ? "do_not_respond_call_family_on_known_number" :
      "do_not_respond_verify_via_official_app";

    var verify = [];
    if (r.verdict !== "no_red_flags" || signals.impersonation.present) verify.push("sender_number");
    if (r.links.some(function (l) { return !l.official || l.suspicious; })) verify.push("link_domain");
    if (byId.reply_call) verify.push("callback_number");

    return {
      signals: signals,
      scam_stage: stage,
      scam_type_guess: type,
      risk: r.verdict,
      confidence: conf,
      recommended_action: action,
      needs_verification: verify,
      links: r.links.map(function (l) {
        return { url: l.url, valid: l.valid, domain: l.domain, status: l.status, problems: l.problems, official_for: l.official };
      })
    };
  }

  var api = { check: check, analyzeLinks: analyzeLinks, BRANDS: BRANDS, detectLanguage: detectLanguage, tokenize: tokenize, FLAGS: FLAGS, VERDICT_TEXT: VERDICT_TEXT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SilverShield = api;
})(typeof window !== "undefined" ? window : globalThis);
