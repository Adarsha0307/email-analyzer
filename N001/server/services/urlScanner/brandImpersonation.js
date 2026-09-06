const BRANDS = [
  { name: 'Google', domains: ['google.com', 'googleapis.com', 'gmail.com', 'youtube.com'] },
  { name: 'Facebook', domains: ['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com', 'meta.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'azure.com', 'linkedin.com'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazonaws.com', 'primevideo.com', 'audible.com'] },
  { name: 'PayPal', domains: ['paypal.com', 'paypalobjects.com'] },
  { name: 'Netflix', domains: ['netflix.com', 'nflximg.com', 'nflxvideo.net'] },
  { name: 'Instagram', domains: ['instagram.com', 'cdninstagram.com'] },
  { name: 'GitHub', domains: ['github.com', 'githubusercontent.com'] },
  { name: 'WhatsApp', domains: ['whatsapp.com', 'whatsapp.net'] },
  { name: 'Telegram', domains: ['telegram.org', 't.me'] },
  { name: 'Discord', domains: ['discord.com', 'discordapp.com', 'discord.gg'] },
  { name: 'Dropbox', domains: ['dropbox.com', 'dropboxstatic.com'] },
  { name: 'Adobe', domains: ['adobe.com', 'adobestock.com'] },
  { name: 'Yahoo', domains: ['yahoo.com', 'yimg.com'] },
  { name: 'eBay', domains: ['ebay.com', 'ebayimg.com', 'ebaystatic.com'] },
  { name: 'Bank of America', domains: ['bankofamerica.com', 'bofa.com'] },
  { name: 'Chase', domains: ['chase.com', 'jpmorgan.com'] },
  { name: 'Wells Fargo', domains: ['wellsfargo.com'] },
  { name: 'Coinbase', domains: ['coinbase.com', 'coinbaseprime.com'] },
  { name: 'Binance', domains: ['binance.com', 'binance.us'] },
];

export function detectBrandImpersonation(hostname, registrableDomain) {
  if (!hostname || !registrableDomain) return [];
  const words = hostname.toLowerCase().split(/[.-]/).filter(Boolean);
  const registered = registrableDomain.toLowerCase();

  return BRANDS.flatMap((brand) => {
    if (brand.domains.includes(registered)) return [];
    const brandParts = brand.name.toLowerCase().split(' ');
    if (!words.some((word) => brandParts.includes(word))) return [];
    return [{
      severity: 'high',
      category: 'brand_impersonation',
      title: `Possible ${brand.name} impersonation`,
      description: `The hostname references ${brand.name}, but ${registrableDomain} is not an official ${brand.name} domain.`,
      brand: brand.name,
    }];
  });
}
