/**
 * Built-in allowlist of well-known domains.
 *
 * Why this exists: the model reads nine purely structural properties of a URL.
 * That is enough to be genuinely useful, but it cannot tell that
 * `stackoverflow.com/questions/tagged/python` is a famous developer site — it
 * only sees a longish path with several segments. On the held-out test set the
 * model raises a false alarm on about 1 legitimate URL in 5 at the default
 * threshold, and interrupting someone on a site they trust is the fastest way
 * to make them disable a security tool for good.
 *
 * So popular domains are never interrupted. This is what production phishing
 * blockers do too. Users can add their own domains from the popup, and the
 * whole mechanism can be switched off in Options.
 */
(function (root) {
  "use strict";

  var DOMAINS = [
    // search, portals, mail
    "google.com", "google.co.uk", "google.co.in", "bing.com", "duckduckgo.com",
    "yahoo.com", "baidu.com", "yandex.com", "ecosia.org", "brave.com",
    "gmail.com", "outlook.com", "live.com", "office.com", "office365.com",
    "protonmail.com", "proton.me", "zoho.com", "icloud.com", "mail.ru",
    // big tech
    "microsoft.com", "apple.com", "amazon.com", "amazon.co.uk", "amazon.in",
    "meta.com", "adobe.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "salesforce.com", "sap.com", "dell.com", "hp.com", "lenovo.com", "cisco.com",
    "vmware.com", "qualcomm.com", "amd.com",
    // dev + cloud
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com", "npmjs.com", "pypi.org", "python.org", "nodejs.org",
    "docker.com", "kubernetes.io", "mozilla.org", "developer.mozilla.org",
    "w3.org", "rust-lang.org", "golang.org", "go.dev", "java.com", "oracle.java.com",
    "jetbrains.com", "visualstudio.com", "vercel.com", "netlify.com",
    "heroku.com", "digitalocean.com", "cloudflare.com", "aws.amazon.com",
    "azure.com", "cloud.google.com", "firebase.google.com", "atlassian.com",
    "jira.com", "confluence.com", "readthedocs.io", "sourceforge.net",
    "codepen.io", "replit.com", "kaggle.com", "huggingface.co", "colab.google",
    "anaconda.com", "scikit-learn.org", "pandas.pydata.org", "numpy.org",
    "tensorflow.org", "pytorch.org", "openai.com", "anthropic.com", "claude.ai",
    // social + media
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "pinterest.com", "tumblr.com", "snapchat.com", "tiktok.com",
    "whatsapp.com", "telegram.org", "discord.com", "slack.com", "zoom.us",
    "teams.microsoft.com", "skype.com", "youtube.com", "vimeo.com", "twitch.tv",
    "netflix.com", "spotify.com", "soundcloud.com", "hulu.com", "primevideo.com",
    "disneyplus.com", "hotstar.com", "medium.com", "substack.com", "quora.com",
    "imgur.com", "flickr.com", "behance.net", "dribbble.com",
    // news + reference
    "wikipedia.org", "wikimedia.org", "bbc.co.uk", "bbc.com", "cnn.com",
    "nytimes.com", "theguardian.com", "reuters.com", "bloomberg.com",
    "forbes.com", "wsj.com", "ft.com", "economist.com", "npr.org",
    "washingtonpost.com", "aljazeera.com", "indiatimes.com", "hindustantimes.com",
    "ndtv.com", "thehindu.com", "timesofindia.com",
    // shopping, travel, finance
    "ebay.com", "etsy.com", "walmart.com", "target.com", "bestbuy.com",
    "aliexpress.com", "alibaba.com", "flipkart.com", "myntra.com", "shopify.com",
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com", "uber.com",
    "lyft.com", "makemytrip.com", "irctc.co.in", "paypal.com", "stripe.com",
    "wise.com", "revolut.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citi.com", "hsbc.com", "barclays.co.uk", "hdfcbank.com", "icicibank.com",
    "sbi.co.in", "axisbank.com", "paytm.com", "phonepe.com", "visa.com",
    "mastercard.com", "americanexpress.com",
    // education, government, health
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org", "mit.edu",
    "stanford.edu", "harvard.edu", "ox.ac.uk", "cam.ac.uk", "nptel.ac.in",
    "scholar.google.com", "arxiv.org", "researchgate.net", "ieee.org",
    "springer.com", "sciencedirect.com", "jstor.org", "nature.com",
    "gov.uk", "usa.gov", "irs.gov", "nih.gov", "cdc.gov", "who.int",
    "europa.eu", "india.gov.in", "nic.in", "uidai.gov.in",
    // infrastructure / misc
    "wordpress.com", "wordpress.org", "wix.com", "squarespace.com", "godaddy.com",
    "namecheap.com", "letsencrypt.org", "archive.org", "gravatar.com",
    "googleapis.com", "gstatic.com", "cloudfront.net", "akamai.com", "jsdelivr.net",
    "unpkg.com", "cdnjs.com", "bit.ly", "dropbox.com", "box.com", "drive.google.com",
    "onedrive.live.com", "docs.google.com", "notion.so", "figma.com", "canva.com",
    "trello.com", "asana.com", "monday.com", "airtable.com", "grammarly.com"
  ];

  var SET = new Set(DOMAINS);

  /**
   * Registrable-ish domain: last two labels, or last three for known
   * two-part public suffixes such as .co.uk / .ac.in.
   */
  var TWO_PART_TLDS = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "gov.in", "net.in",
    "org.in", "co.jp", "co.kr", "com.au", "net.au", "org.au", "com.br",
    "com.cn", "com.mx", "co.za", "com.sg", "co.nz", "com.tr", "com.tw"
  ]);

  function registrableDomain(hostname) {
    var host = (hostname || "").toLowerCase().replace(/\.$/, "");
    var parts = host.split(".");
    if (parts.length <= 2) return host;
    var lastTwo = parts.slice(-2).join(".");
    if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  /** True when the hostname is, or sits under, a well-known domain. */
  function isBuiltInTrusted(hostname) {
    var host = (hostname || "").toLowerCase();
    if (SET.has(host)) return true;
    return SET.has(registrableDomain(host));
  }

  root.PhishAllowlist = {
    DOMAINS: DOMAINS,
    registrableDomain: registrableDomain,
    isBuiltInTrusted: isBuiltInTrusted
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.PhishAllowlist;
  }
})(typeof self !== "undefined" ? self : this);
