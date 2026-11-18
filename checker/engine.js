// Silver Shield scam checker engine.
// Works in the browser (window.SilverShield) and in Node (require).
// Two signals:
//   1. Red-flag rules: explainable patterns in English, Spanish and Chinese.
//   2. A naive Bayes word model trained on the UCI SMS Spam Collection (English only).
// Three verdicts, never "safe": likely_scam, cannot_tell, no_red_flags.
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
        "password", "\\bpin\\b", "social security( number)?", "\\bssn\\b", "one[- ]time (pass)?code",
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
        "will be (suspended|locked|closed|cancelled|canceled)", "expires? (today|soon|in)", "last chance", "avoid (penalt|late fee|suspension|legal)",
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
        "wells fargo", "chase", "bank of america", "\\bbank\\b", "social security administration", "medicare",
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

  var URL_RE = /\b((https?:\/\/|www\.)[^\s]+|[a-z0-9-]+\.(com|net|org|info|top|xyz|click|link|vip|shop|online|site|live|cc|ly|io|co|me|biz|us|cn)(\/[^\s]*)?)/gi;
  var SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|rb\.gy|cutt\.ly|shorturl\.at|tiny\.cc)\b/i;
  var ODD_TLD = /\.(top|xyz|click|link|vip|shop|online|site|live|cc|info|biz|cn)\b/i;
  var IP_URL = /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i;
  var BRAND_IN_HOST = /\b(usps|fedex|ups|dhl|amazon|paypal|apple|netflix|chase|wellsfargo|wells-fargo|bankofamerica|irs|dmv|fastrak|ezpass|toll)[a-z0-9]*[-.][a-z0-9-]+\.(?!gov\b)[a-z]{2,}/i;

  var LINK_TEXT = {
    en: "It contains a link. Do not tap links in unexpected messages; type the company's address yourself.",
    es: "Contiene un enlace. No toque enlaces en mensajes inesperados; escriba usted mismo la dirección de la empresa.",
    zh: "它包含链接。不要点击陌生短信中的链接，请自己输入官方网址。"
  };
  var BAD_LINK_TEXT = {
    en: "The link is disguised: a short link, an unusual web ending, or a company name inside a look-alike address. That is a strong scam sign.",
    es: "El enlace está disfrazado: enlace acortado, terminación web inusual o el nombre de una empresa dentro de una dirección falsa. Es una señal fuerte de estafa.",
    zh: "链接经过伪装：短链接、少见的域名后缀，或在仿冒网址中嵌入公司名称。这是很强的诈骗信号。"
  };

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

    if (useRules) {
      compiled.forEach(function (c) {
        var m = text.match(c.re);
        if (m) {
          flags.push({ id: c.flag.id, weight: c.flag.weight, match: m[0], text: c.flag.text });
          score += c.flag.weight;
        }
      });

      var urls = text.match(URL_RE) || [];
      if (urls.length) {
        var bad = urls.some(function (u) { return SHORTENERS.test(u) || ODD_TLD.test(u) || IP_URL.test(u) || BRAND_IN_HOST.test(u); });
        if (bad) {
          flags.push({ id: "bad_link", weight: 2.5, match: urls[0], text: BAD_LINK_TEXT });
          score += 2.5;
        } else {
          flags.push({ id: "link", weight: 1, match: urls[0], text: LINK_TEXT });
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

    return {
      verdict: verdict,
      verdictText: VERDICT_TEXT[verdict][lang],
      lang: lang,
      score: score,
      modelProbability: p,
      flags: flags.map(function (f) { return { id: f.id, match: f.match, explanation: f.text[lang] }; }),
      caveat: verdict === "no_red_flags" ? CAVEAT_TEXT[lang] : null,
      nextSteps: NEXT_STEPS[lang]
    };
  }

  var api = { check: check, detectLanguage: detectLanguage, tokenize: tokenize, FLAGS: FLAGS, VERDICT_TEXT: VERDICT_TEXT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SilverShield = api;
})(typeof window !== "undefined" ? window : globalThis);
