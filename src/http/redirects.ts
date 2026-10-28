export interface RedirectAnalysis {
  chain: string[];
  count: number;
  hasLoop: boolean;
  exceededLimit: boolean;
  finalDestination: string | null;
  firstProhibitedHop: string | null;
}

export function analyzeRedirectChain(
  chain: string[],
  maxRedirects: number,
  isProhibited: (url: string) => boolean
): RedirectAnalysis {
  let hasLoop = false;
  let exceededLimit = false;
  let firstProhibitedHop: string | null = null;

  const seen = new Set<string>();
  for (const url of chain) {
    if (seen.has(url)) {
      hasLoop = true;
      break;
    }
    seen.add(url);
    if (isProhibited(url) && firstProhibitedHop === null) {
      firstProhibitedHop = url;
    }
  }

  exceededLimit = chain.length - 1 > maxRedirects;

  return {
    chain,
    count: Math.max(chain.length - 1, 0),
    hasLoop,
    exceededLimit,
    finalDestination: chain.length > 0 ? chain[chain.length - 1] : null,
    firstProhibitedHop,
  };
}

export function isRedirectStatus(statusCode: number): boolean {
  return statusCode >= 300 && statusCode < 400;
}
