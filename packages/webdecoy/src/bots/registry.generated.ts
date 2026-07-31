/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Source of truth: WebDecoy/app `pkg/agents` (Go).
 * Regenerate with `packages/webdecoy/scripts/gen-bot-registry.mjs`; see that
 * script for the command.
 *
 * ORDER IS SIGNIFICANT. Entries are in `agents.MatchUserAgent` order — AI data
 * scrapers first, then AI search crawlers, AI agents, search engines, then the
 * remaining categories. `matchUserAgent()` returns the first hit, and several
 * agents share User-Agent substrings, so sorting this array changes how real
 * traffic is classified.
 *
 * 168 agents across 15 categories.
 */

/**
 * Classification categories, mirroring `agents.Category` in Go.
 *
 * Declared here rather than hand-written next door so a category added in Go
 * cannot go missing in TypeScript.
 */
export type BotCategory =
  | "training_crawler"
  | "ai_search_crawler"
  | "ai_agent"
  | "ai_assistant"
  | "search_crawler"
  | "seo_crawler"
  | "security_scanner"
  | "generic_scraper"
  | "archiver"
  | "fetcher"
  | "monitoring"
  | "headless_browser"
  | "feed_reader"
  | "commercial_scraper"
  | "none";

/** One entry in the registry. */
export interface BotAgent {
  /** Stable lowercase slug, e.g. `gptbot`. */
  id: string;
  /** Display name, e.g. `GPTBot`. */
  name: string;
  category: BotCategory;
  /** Operator, e.g. `OpenAI`. */
  organization: string;
  /** The registry's default threat score for this agent (0-100). */
  baseScore: number;
  /** Whether the operator documents honouring robots.txt. */
  respectsRobots: boolean;
  /** Lowercase User-Agent substrings that identify it. */
  uaPatterns: readonly string[];
}

/** Every declared category, including any with no agents yet. */
export const BOT_CATEGORIES: readonly BotCategory[] = [
  "training_crawler",
  "ai_search_crawler",
  "ai_agent",
  "ai_assistant",
  "search_crawler",
  "seo_crawler",
  "security_scanner",
  "generic_scraper",
  "archiver",
  "fetcher",
  "monitoring",
  "headless_browser",
  "feed_reader",
  "commercial_scraper",
  "none",
];

/** The agent table, in match order. */
export const BOT_REGISTRY: readonly BotAgent[] = [
  { id: "gptbot", name: "GPTBot", category: "training_crawler", organization: "OpenAI", baseScore: 85, respectsRobots: true, uaPatterns: ["gptbot"] },
  { id: "chatgpt-user", name: "ChatGPT-User", category: "training_crawler", organization: "OpenAI", baseScore: 85, respectsRobots: true, uaPatterns: ["chatgpt-user", "chatgpt"] },
  { id: "oai-searchbot", name: "OAI-SearchBot", category: "training_crawler", organization: "OpenAI", baseScore: 80, respectsRobots: true, uaPatterns: ["oai-searchbot"] },
  { id: "claudebot", name: "ClaudeBot", category: "training_crawler", organization: "Anthropic", baseScore: 85, respectsRobots: true, uaPatterns: ["claudebot"] },
  { id: "anthropic", name: "Anthropic", category: "training_crawler", organization: "Anthropic", baseScore: 85, respectsRobots: true, uaPatterns: ["anthropic"] },
  { id: "ccbot", name: "CCBot", category: "training_crawler", organization: "Common Crawl", baseScore: 80, respectsRobots: true, uaPatterns: ["ccbot"] },
  { id: "google-extended", name: "Google-Extended", category: "training_crawler", organization: "Google", baseScore: 80, respectsRobots: true, uaPatterns: ["google-extended"] },
  { id: "bytespider", name: "ByteSpider", category: "training_crawler", organization: "ByteDance", baseScore: 75, respectsRobots: false, uaPatterns: ["bytespider"] },
  { id: "amazonbot", name: "Amazonbot", category: "training_crawler", organization: "Amazon", baseScore: 70, respectsRobots: true, uaPatterns: ["amazonbot"] },
  { id: "facebookbot", name: "FacebookBot", category: "training_crawler", organization: "Meta", baseScore: 70, respectsRobots: true, uaPatterns: ["facebookbot"] },
  { id: "meta-externalagent", name: "Meta-ExternalAgent", category: "training_crawler", organization: "Meta", baseScore: 75, respectsRobots: true, uaPatterns: ["meta-externalagent"] },
  { id: "cohere-ai", name: "Cohere", category: "training_crawler", organization: "Cohere", baseScore: 80, respectsRobots: true, uaPatterns: ["cohere-ai", "cohere"] },
  { id: "perplexitybot", name: "PerplexityBot", category: "training_crawler", organization: "Perplexity AI", baseScore: 80, respectsRobots: true, uaPatterns: ["perplexitybot"] },
  { id: "applebot-extended", name: "Applebot-Extended", category: "training_crawler", organization: "Apple", baseScore: 75, respectsRobots: true, uaPatterns: ["applebot-extended"] },
  { id: "youbot", name: "YouBot", category: "training_crawler", organization: "You.com", baseScore: 75, respectsRobots: true, uaPatterns: ["youbot"] },
  { id: "mistral", name: "MistralBot", category: "training_crawler", organization: "Mistral AI", baseScore: 80, respectsRobots: true, uaPatterns: ["mistral"] },
  { id: "gemini", name: "Gemini", category: "training_crawler", organization: "Google", baseScore: 80, respectsRobots: true, uaPatterns: ["gemini"] },
  { id: "ai2bot", name: "AI2Bot", category: "training_crawler", organization: "Allen Institute for AI", baseScore: 75, respectsRobots: true, uaPatterns: ["ai2bot"] },
  { id: "deepseek", name: "DeepSeek", category: "training_crawler", organization: "DeepSeek", baseScore: 80, respectsRobots: true, uaPatterns: ["deepseek"] },
  { id: "qwen", name: "Qwen", category: "training_crawler", organization: "Alibaba", baseScore: 75, respectsRobots: true, uaPatterns: ["qwen"] },
  { id: "webzio", name: "Webz.io", category: "training_crawler", organization: "Webz.io", baseScore: 70, respectsRobots: false, uaPatterns: ["webzio"] },
  { id: "sentibot", name: "Sentibot", category: "training_crawler", organization: "Sentibot", baseScore: 70, respectsRobots: false, uaPatterns: ["sentibot"] },
  { id: "omgili", name: "Omgili", category: "training_crawler", organization: "Webz.io", baseScore: 70, respectsRobots: false, uaPatterns: ["omgili"] },
  { id: "img2dataset", name: "img2dataset", category: "training_crawler", organization: "LAION", baseScore: 75, respectsRobots: false, uaPatterns: ["img2dataset"] },
  { id: "timpibot", name: "Timpibot", category: "training_crawler", organization: "Timpi", baseScore: 70, respectsRobots: true, uaPatterns: ["timpibot"] },
  { id: "velenpublicwebcrawler", name: "VelenPublicWebCrawler", category: "training_crawler", organization: "Velen", baseScore: 70, respectsRobots: false, uaPatterns: ["velenpublicwebcrawler"] },
  { id: "isscyberriskcrawler", name: "ISSCyberRiskCrawler", category: "training_crawler", organization: "ISS", baseScore: 65, respectsRobots: false, uaPatterns: ["isscyberriskcrawler"] },
  { id: "friendlycrawler", name: "FriendlyCrawler", category: "training_crawler", organization: "Unknown", baseScore: 65, respectsRobots: true, uaPatterns: ["friendlycrawler"] },
  { id: "searchgpt", name: "SearchGPT", category: "ai_search_crawler", organization: "OpenAI", baseScore: 75, respectsRobots: true, uaPatterns: ["searchgpt"] },
  { id: "phind", name: "Phind", category: "ai_search_crawler", organization: "Phind", baseScore: 70, respectsRobots: true, uaPatterns: ["phind"] },
  { id: "kagi", name: "Kagi", category: "ai_search_crawler", organization: "Kagi", baseScore: 65, respectsRobots: true, uaPatterns: ["kagi"] },
  { id: "exa", name: "Exa", category: "ai_search_crawler", organization: "Exa AI", baseScore: 70, respectsRobots: true, uaPatterns: ["exa.ai", "exabot"] },
  { id: "metaphor", name: "Metaphor", category: "ai_search_crawler", organization: "Metaphor", baseScore: 70, respectsRobots: true, uaPatterns: ["metaphor"] },
  { id: "tavily", name: "Tavily", category: "ai_search_crawler", organization: "Tavily", baseScore: 70, respectsRobots: true, uaPatterns: ["tavily"] },
  { id: "brave-search", name: "BraveSearch", category: "ai_search_crawler", organization: "Brave", baseScore: 65, respectsRobots: true, uaPatterns: ["bravesearch"] },
  { id: "neeva", name: "NeevaBot", category: "ai_search_crawler", organization: "Neeva", baseScore: 65, respectsRobots: true, uaPatterns: ["neevabot"] },
  { id: "operator", name: "Operator", category: "ai_agent", organization: "OpenAI", baseScore: 75, respectsRobots: true, uaPatterns: ["operator"] },
  { id: "claude-user", name: "Claude-User", category: "ai_agent", organization: "Anthropic", baseScore: 75, respectsRobots: true, uaPatterns: ["claude-user"] },
  { id: "gemini-user", name: "Gemini-User", category: "ai_agent", organization: "Google", baseScore: 75, respectsRobots: true, uaPatterns: ["gemini-user"] },
  { id: "googleagent-mariner", name: "GoogleAgent-Mariner", category: "ai_agent", organization: "Google", baseScore: 75, respectsRobots: true, uaPatterns: ["googleagent-mariner", "mariner"] },
  { id: "amazon-buyforme", name: "AmazonBuyForMe", category: "ai_agent", organization: "Amazon", baseScore: 70, respectsRobots: true, uaPatterns: ["amazonbuyforme", "buyforme"] },
  { id: "browser-use", name: "Browser-Use", category: "ai_agent", organization: "Open Source", baseScore: 70, respectsRobots: false, uaPatterns: ["browser-use"] },
  { id: "stagehand", name: "Stagehand", category: "ai_agent", organization: "Browserbase", baseScore: 70, respectsRobots: false, uaPatterns: ["stagehand"] },
  { id: "multion", name: "MultiOn", category: "ai_agent", organization: "MultiOn", baseScore: 70, respectsRobots: false, uaPatterns: ["multion"] },
  { id: "googlebot", name: "Googlebot", category: "search_crawler", organization: "Google", baseScore: 30, respectsRobots: true, uaPatterns: ["googlebot"] },
  { id: "bingbot", name: "Bingbot", category: "search_crawler", organization: "Microsoft", baseScore: 30, respectsRobots: true, uaPatterns: ["bingbot"] },
  { id: "yandexbot", name: "YandexBot", category: "search_crawler", organization: "Yandex", baseScore: 35, respectsRobots: true, uaPatterns: ["yandexbot"] },
  { id: "baiduspider", name: "Baiduspider", category: "search_crawler", organization: "Baidu", baseScore: 40, respectsRobots: true, uaPatterns: ["baiduspider"] },
  { id: "duckduckbot", name: "DuckDuckBot", category: "search_crawler", organization: "DuckDuckGo", baseScore: 30, respectsRobots: true, uaPatterns: ["duckduckbot"] },
  { id: "applebot", name: "Applebot", category: "search_crawler", organization: "Apple", baseScore: 30, respectsRobots: true, uaPatterns: ["applebot"] },
  { id: "sogou", name: "Sogou Spider", category: "search_crawler", organization: "Sogou", baseScore: 40, respectsRobots: true, uaPatterns: ["sogou"] },
  { id: "qwantify", name: "Qwantify", category: "search_crawler", organization: "Qwant", baseScore: 35, respectsRobots: true, uaPatterns: ["qwantify"] },
  { id: "naver", name: "Naver", category: "search_crawler", organization: "Naver", baseScore: 35, respectsRobots: true, uaPatterns: ["naver", "yeti"] },
  { id: "seznam", name: "SeznamBot", category: "search_crawler", organization: "Seznam", baseScore: 35, respectsRobots: true, uaPatterns: ["seznambot"] },
  { id: "ecosia", name: "Ecosia", category: "search_crawler", organization: "Ecosia", baseScore: 30, respectsRobots: true, uaPatterns: ["ecosia"] },
  { id: "mojeek", name: "MojeekBot", category: "search_crawler", organization: "Mojeek", baseScore: 35, respectsRobots: true, uaPatterns: ["mojeekbot"] },
  { id: "yahoo-slurp", name: "Yahoo! Slurp", category: "search_crawler", organization: "Yahoo", baseScore: 30, respectsRobots: true, uaPatterns: ["slurp"] },
  { id: "ahrefsbot", name: "AhrefsBot", category: "seo_crawler", organization: "Ahrefs", baseScore: 50, respectsRobots: true, uaPatterns: ["ahrefsbot", "ahrefs"] },
  { id: "semrushbot", name: "SemrushBot", category: "seo_crawler", organization: "Semrush", baseScore: 50, respectsRobots: true, uaPatterns: ["semrushbot", "semrush"] },
  { id: "mj12bot", name: "MJ12bot", category: "seo_crawler", organization: "Majestic", baseScore: 50, respectsRobots: true, uaPatterns: ["mj12bot"] },
  { id: "dotbot", name: "DotBot", category: "seo_crawler", organization: "Moz", baseScore: 50, respectsRobots: true, uaPatterns: ["dotbot"] },
  { id: "rogerbot", name: "Rogerbot", category: "seo_crawler", organization: "Moz", baseScore: 50, respectsRobots: true, uaPatterns: ["rogerbot"] },
  { id: "screaming-frog", name: "Screaming Frog", category: "seo_crawler", organization: "Screaming Frog", baseScore: 55, respectsRobots: true, uaPatterns: ["screaming frog"] },
  { id: "sitebulb", name: "Sitebulb", category: "seo_crawler", organization: "Sitebulb", baseScore: 55, respectsRobots: true, uaPatterns: ["sitebulb"] },
  { id: "deepcrawl", name: "DeepCrawl", category: "seo_crawler", organization: "Lumar", baseScore: 50, respectsRobots: true, uaPatterns: ["deepcrawl"] },
  { id: "oncrawl", name: "OnCrawl", category: "seo_crawler", organization: "OnCrawl", baseScore: 50, respectsRobots: true, uaPatterns: ["oncrawl"] },
  { id: "botify", name: "Botify", category: "seo_crawler", organization: "Botify", baseScore: 50, respectsRobots: true, uaPatterns: ["botify"] },
  { id: "contentking", name: "ContentKing", category: "seo_crawler", organization: "ContentKing", baseScore: 50, respectsRobots: true, uaPatterns: ["contentking"] },
  { id: "sistrix", name: "SISTRIX", category: "seo_crawler", organization: "SISTRIX", baseScore: 50, respectsRobots: true, uaPatterns: ["sistrix"] },
  { id: "serpstat", name: "Serpstat", category: "seo_crawler", organization: "Serpstat", baseScore: 50, respectsRobots: true, uaPatterns: ["serpstat"] },
  { id: "spyfu", name: "SpyFu", category: "seo_crawler", organization: "SpyFu", baseScore: 50, respectsRobots: true, uaPatterns: ["spyfu"] },
  { id: "nessus", name: "Nessus", category: "security_scanner", organization: "Tenable", baseScore: 70, respectsRobots: false, uaPatterns: ["nessus"] },
  { id: "qualys", name: "Qualys", category: "security_scanner", organization: "Qualys", baseScore: 70, respectsRobots: false, uaPatterns: ["qualys"] },
  { id: "shodan", name: "Shodan", category: "security_scanner", organization: "Shodan", baseScore: 75, respectsRobots: false, uaPatterns: ["shodan"] },
  { id: "censys", name: "Censys", category: "security_scanner", organization: "Censys", baseScore: 75, respectsRobots: false, uaPatterns: ["censys"] },
  { id: "nmap", name: "Nmap", category: "security_scanner", organization: "Open Source", baseScore: 70, respectsRobots: false, uaPatterns: ["nmap"] },
  { id: "zap", name: "OWASP ZAP", category: "security_scanner", organization: "OWASP", baseScore: 70, respectsRobots: false, uaPatterns: ["zap/"] },
  { id: "burp", name: "Burp Suite", category: "security_scanner", organization: "PortSwigger", baseScore: 70, respectsRobots: false, uaPatterns: ["burp"] },
  { id: "nikto", name: "Nikto", category: "security_scanner", organization: "Open Source", baseScore: 70, respectsRobots: false, uaPatterns: ["nikto"] },
  { id: "nuclei", name: "Nuclei", category: "security_scanner", organization: "ProjectDiscovery", baseScore: 70, respectsRobots: false, uaPatterns: ["nuclei"] },
  { id: "acunetix", name: "Acunetix", category: "security_scanner", organization: "Invicti", baseScore: 70, respectsRobots: false, uaPatterns: ["acunetix"] },
  { id: "netsparker", name: "Netsparker", category: "security_scanner", organization: "Invicti", baseScore: 70, respectsRobots: false, uaPatterns: ["netsparker"] },
  { id: "detectify", name: "Detectify", category: "security_scanner", organization: "Detectify", baseScore: 65, respectsRobots: false, uaPatterns: ["detectify"] },
  { id: "intruder", name: "Intruder", category: "security_scanner", organization: "Intruder", baseScore: 65, respectsRobots: false, uaPatterns: ["intruder"] },
  { id: "python-requests", name: "Python-Requests", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["python-requests"] },
  { id: "python-urllib", name: "Python-urllib", category: "generic_scraper", organization: "Python", baseScore: 55, respectsRobots: false, uaPatterns: ["python-urllib"] },
  { id: "python", name: "Python", category: "generic_scraper", organization: "Python", baseScore: 50, respectsRobots: false, uaPatterns: ["python/"] },
  { id: "scrapy", name: "Scrapy", category: "generic_scraper", organization: "Scrapy", baseScore: 65, respectsRobots: true, uaPatterns: ["scrapy"] },
  { id: "httpx", name: "HTTPX", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["httpx"] },
  { id: "aiohttp", name: "aiohttp", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["aiohttp"] },
  { id: "beautifulsoup", name: "BeautifulSoup", category: "generic_scraper", organization: "Open Source", baseScore: 60, respectsRobots: false, uaPatterns: ["beautifulsoup"] },
  { id: "node-fetch", name: "node-fetch", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["node-fetch"] },
  { id: "axios", name: "Axios", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["axios/"] },
  { id: "got", name: "Got", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["got/"] },
  { id: "undici", name: "Undici", category: "generic_scraper", organization: "Node.js", baseScore: 55, respectsRobots: false, uaPatterns: ["undici"] },
  { id: "go-http-client", name: "Go-HTTP-Client", category: "generic_scraper", organization: "Go", baseScore: 55, respectsRobots: false, uaPatterns: ["go-http-client"] },
  { id: "colly", name: "Colly", category: "generic_scraper", organization: "Open Source", baseScore: 65, respectsRobots: true, uaPatterns: ["colly"] },
  { id: "java", name: "Java", category: "generic_scraper", organization: "Oracle", baseScore: 50, respectsRobots: false, uaPatterns: ["java/"] },
  { id: "okhttp", name: "OkHttp", category: "generic_scraper", organization: "Square", baseScore: 55, respectsRobots: false, uaPatterns: ["okhttp"] },
  { id: "apache-httpclient", name: "Apache-HttpClient", category: "generic_scraper", organization: "Apache", baseScore: 55, respectsRobots: false, uaPatterns: ["apache-httpclient"] },
  { id: "jsoup", name: "Jsoup", category: "generic_scraper", organization: "Open Source", baseScore: 60, respectsRobots: false, uaPatterns: ["jsoup"] },
  { id: "guzzlehttp", name: "GuzzleHttp", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["guzzlehttp"] },
  { id: "php", name: "PHP", category: "generic_scraper", organization: "PHP", baseScore: 50, respectsRobots: false, uaPatterns: ["php/"] },
  { id: "ruby", name: "Ruby", category: "generic_scraper", organization: "Ruby", baseScore: 50, respectsRobots: false, uaPatterns: ["ruby"] },
  { id: "faraday", name: "Faraday", category: "generic_scraper", organization: "Open Source", baseScore: 55, respectsRobots: false, uaPatterns: ["faraday"] },
  { id: "mechanize", name: "Mechanize", category: "generic_scraper", organization: "Open Source", baseScore: 60, respectsRobots: false, uaPatterns: ["mechanize"] },
  { id: "headlesschrome", name: "HeadlessChrome", category: "headless_browser", organization: "Google", baseScore: 70, respectsRobots: false, uaPatterns: ["headlesschrome"] },
  { id: "puppeteer", name: "Puppeteer", category: "headless_browser", organization: "Google", baseScore: 70, respectsRobots: false, uaPatterns: ["puppeteer"] },
  { id: "playwright", name: "Playwright", category: "headless_browser", organization: "Microsoft", baseScore: 70, respectsRobots: false, uaPatterns: ["playwright"] },
  { id: "selenium", name: "Selenium", category: "headless_browser", organization: "Open Source", baseScore: 70, respectsRobots: false, uaPatterns: ["selenium"] },
  { id: "phantomjs", name: "PhantomJS", category: "headless_browser", organization: "Open Source", baseScore: 75, respectsRobots: false, uaPatterns: ["phantomjs"] },
  { id: "splash", name: "Splash", category: "headless_browser", organization: "Scrapinghub", baseScore: 70, respectsRobots: false, uaPatterns: ["splash"] },
  { id: "browserless", name: "Browserless", category: "headless_browser", organization: "Browserless", baseScore: 65, respectsRobots: false, uaPatterns: ["browserless"] },
  { id: "browserbase", name: "Browserbase", category: "headless_browser", organization: "Browserbase", baseScore: 65, respectsRobots: false, uaPatterns: ["browserbase"] },
  { id: "ia-archiver", name: "Internet Archive", category: "archiver", organization: "Internet Archive", baseScore: 25, respectsRobots: true, uaPatterns: ["ia_archiver"] },
  { id: "archive-org-bot", name: "Archive.org", category: "archiver", organization: "Internet Archive", baseScore: 25, respectsRobots: true, uaPatterns: ["archive.org_bot"] },
  { id: "wayback", name: "Wayback Machine", category: "archiver", organization: "Internet Archive", baseScore: 25, respectsRobots: true, uaPatterns: ["wayback"] },
  { id: "heritrix", name: "Heritrix", category: "archiver", organization: "Internet Archive", baseScore: 30, respectsRobots: true, uaPatterns: ["heritrix"] },
  { id: "brozzler", name: "Brozzler", category: "archiver", organization: "Internet Archive", baseScore: 30, respectsRobots: true, uaPatterns: ["brozzler"] },
  { id: "facebookexternalhit", name: "Facebook", category: "fetcher", organization: "Meta", baseScore: 25, respectsRobots: true, uaPatterns: ["facebookexternalhit"] },
  { id: "twitterbot", name: "Twitterbot", category: "fetcher", organization: "X Corp", baseScore: 25, respectsRobots: true, uaPatterns: ["twitterbot"] },
  { id: "linkedinbot", name: "LinkedInBot", category: "fetcher", organization: "LinkedIn", baseScore: 25, respectsRobots: true, uaPatterns: ["linkedinbot"] },
  { id: "slackbot", name: "Slackbot", category: "fetcher", organization: "Slack", baseScore: 25, respectsRobots: true, uaPatterns: ["slackbot"] },
  { id: "telegrambot", name: "TelegramBot", category: "fetcher", organization: "Telegram", baseScore: 25, respectsRobots: true, uaPatterns: ["telegrambot"] },
  { id: "whatsapp", name: "WhatsApp", category: "fetcher", organization: "Meta", baseScore: 25, respectsRobots: true, uaPatterns: ["whatsapp"] },
  { id: "discordbot", name: "Discordbot", category: "fetcher", organization: "Discord", baseScore: 25, respectsRobots: true, uaPatterns: ["discordbot"] },
  { id: "pinterestbot", name: "Pinterest", category: "fetcher", organization: "Pinterest", baseScore: 30, respectsRobots: true, uaPatterns: ["pinterest"] },
  { id: "tumblr", name: "Tumblr", category: "fetcher", organization: "Automattic", baseScore: 30, respectsRobots: true, uaPatterns: ["tumblr"] },
  { id: "reddit", name: "Reddit", category: "fetcher", organization: "Reddit", baseScore: 30, respectsRobots: true, uaPatterns: ["reddit"] },
  { id: "embedly", name: "Embedly", category: "fetcher", organization: "Medium", baseScore: 30, respectsRobots: true, uaPatterns: ["embedly"] },
  { id: "iframely", name: "Iframely", category: "fetcher", organization: "Iframely", baseScore: 30, respectsRobots: true, uaPatterns: ["iframely"] },
  { id: "curl", name: "cURL", category: "fetcher", organization: "Open Source", baseScore: 45, respectsRobots: false, uaPatterns: ["curl/"] },
  { id: "wget", name: "Wget", category: "fetcher", organization: "GNU", baseScore: 45, respectsRobots: false, uaPatterns: ["wget/"] },
  { id: "libwww-perl", name: "libwww-perl", category: "fetcher", organization: "Perl", baseScore: 50, respectsRobots: false, uaPatterns: ["libwww-perl"] },
  { id: "lwp", name: "LWP", category: "fetcher", organization: "Perl", baseScore: 50, respectsRobots: false, uaPatterns: ["lwp-"] },
  { id: "httrack", name: "HTTrack", category: "fetcher", organization: "Open Source", baseScore: 60, respectsRobots: true, uaPatterns: ["httrack"] },
  { id: "uptimerobot", name: "UptimeRobot", category: "monitoring", organization: "UptimeRobot", baseScore: 20, respectsRobots: true, uaPatterns: ["uptimerobot"] },
  { id: "pingdom", name: "Pingdom", category: "monitoring", organization: "SolarWinds", baseScore: 20, respectsRobots: true, uaPatterns: ["pingdom"] },
  { id: "statuscake", name: "StatusCake", category: "monitoring", organization: "StatusCake", baseScore: 20, respectsRobots: true, uaPatterns: ["statuscake"] },
  { id: "better-uptime", name: "Better Uptime", category: "monitoring", organization: "Better Stack", baseScore: 20, respectsRobots: true, uaPatterns: ["betteruptime"] },
  { id: "datadog-synthetics", name: "Datadog Synthetics", category: "monitoring", organization: "Datadog", baseScore: 25, respectsRobots: true, uaPatterns: ["datadog"] },
  { id: "newrelic", name: "New Relic", category: "monitoring", organization: "New Relic", baseScore: 25, respectsRobots: true, uaPatterns: ["newrelic"] },
  { id: "site24x7", name: "Site24x7", category: "monitoring", organization: "Zoho", baseScore: 20, respectsRobots: true, uaPatterns: ["site24x7"] },
  { id: "freshping", name: "Freshping", category: "monitoring", organization: "Freshworks", baseScore: 20, respectsRobots: true, uaPatterns: ["freshping"] },
  { id: "hetrixtools", name: "HetrixTools", category: "monitoring", organization: "HetrixTools", baseScore: 20, respectsRobots: true, uaPatterns: ["hetrixtools"] },
  { id: "nodeping", name: "NodePing", category: "monitoring", organization: "NodePing", baseScore: 20, respectsRobots: true, uaPatterns: ["nodeping"] },
  { id: "feedly", name: "Feedly", category: "feed_reader", organization: "Feedly", baseScore: 25, respectsRobots: true, uaPatterns: ["feedly"] },
  { id: "newsblur", name: "NewsBlur", category: "feed_reader", organization: "NewsBlur", baseScore: 25, respectsRobots: true, uaPatterns: ["newsblur"] },
  { id: "inoreader", name: "Inoreader", category: "feed_reader", organization: "Inoreader", baseScore: 25, respectsRobots: true, uaPatterns: ["inoreader"] },
  { id: "theoldreader", name: "The Old Reader", category: "feed_reader", organization: "The Old Reader", baseScore: 25, respectsRobots: true, uaPatterns: ["theoldreader"] },
  { id: "feedbin", name: "Feedbin", category: "feed_reader", organization: "Feedbin", baseScore: 25, respectsRobots: true, uaPatterns: ["feedbin"] },
  { id: "miniflux", name: "Miniflux", category: "feed_reader", organization: "Open Source", baseScore: 25, respectsRobots: true, uaPatterns: ["miniflux"] },
  { id: "freshrss", name: "FreshRSS", category: "feed_reader", organization: "Open Source", baseScore: 25, respectsRobots: true, uaPatterns: ["freshrss"] },
  { id: "commafeed", name: "CommaFeed", category: "feed_reader", organization: "Open Source", baseScore: 25, respectsRobots: true, uaPatterns: ["commafeed"] },
  { id: "diffbot", name: "Diffbot", category: "commercial_scraper", organization: "Diffbot", baseScore: 70, respectsRobots: true, uaPatterns: ["diffbot"] },
  { id: "import-io", name: "Import.io", category: "commercial_scraper", organization: "Import.io", baseScore: 65, respectsRobots: true, uaPatterns: ["import.io"] },
  { id: "bright-data", name: "Bright Data", category: "commercial_scraper", organization: "Bright Data", baseScore: 70, respectsRobots: false, uaPatterns: ["brightdata", "luminati"] },
  { id: "oxylabs", name: "Oxylabs", category: "commercial_scraper", organization: "Oxylabs", baseScore: 70, respectsRobots: false, uaPatterns: ["oxylabs"] },
  { id: "scrapingbee", name: "ScrapingBee", category: "commercial_scraper", organization: "ScrapingBee", baseScore: 65, respectsRobots: true, uaPatterns: ["scrapingbee"] },
  { id: "scrapingant", name: "ScrapingAnt", category: "commercial_scraper", organization: "ScrapingAnt", baseScore: 65, respectsRobots: true, uaPatterns: ["scrapingant"] },
  { id: "zyte", name: "Zyte", category: "commercial_scraper", organization: "Zyte", baseScore: 65, respectsRobots: true, uaPatterns: ["zyte", "scrapinghub"] },
  { id: "apify", name: "Apify", category: "commercial_scraper", organization: "Apify", baseScore: 65, respectsRobots: true, uaPatterns: ["apify"] },
  { id: "crawlbase", name: "Crawlbase", category: "commercial_scraper", organization: "Crawlbase", baseScore: 65, respectsRobots: true, uaPatterns: ["crawlbase"] },
  { id: "webscrapingapi", name: "WebScrapingAPI", category: "commercial_scraper", organization: "WebScrapingAPI", baseScore: 65, respectsRobots: true, uaPatterns: ["webscrapingapi"] },
  { id: "gemini-deep-research", name: "Gemini-Deep-Research", category: "ai_assistant", organization: "Google", baseScore: 65, respectsRobots: true, uaPatterns: ["gemini-deep-research"] },
  { id: "copilot", name: "Microsoft Copilot", category: "ai_assistant", organization: "Microsoft", baseScore: 65, respectsRobots: true, uaPatterns: ["copilot"] },
  { id: "cortana", name: "Cortana", category: "ai_assistant", organization: "Microsoft", baseScore: 60, respectsRobots: true, uaPatterns: ["cortana"] },
  { id: "siri", name: "Siri", category: "ai_assistant", organization: "Apple", baseScore: 60, respectsRobots: true, uaPatterns: ["siri"] },
];
