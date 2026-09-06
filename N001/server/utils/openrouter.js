const API_URL = 'https://openrouter.ai/api/v1/chat/completions';
const DEFAULT_MODEL = 'openai/gpt-4o-mini';
const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504, 529]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function askOpenRouter(prompt, systemInstruction, jsonMode = false) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) return null;

  const payload = {
    model: process.env.OPENROUTER_MODEL || DEFAULT_MODEL,
    messages: [
      { role: 'system', content: systemInstruction },
      { role: 'user', content: prompt },
    ],
    ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
  };

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
          'X-Title': 'N001 Threat Analyzer',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (response.ok) {
        const data = await response.json();
        return data.choices?.[0]?.message?.content?.trim() || null;
      }
      if (!RETRYABLE_STATUS.has(response.status)) return null;
    } catch (error) {
      if (error.name !== 'AbortError') console.error('[openrouter]', error.message);
    } finally {
      clearTimeout(timer);
    }
    await sleep((attempt + 1) * 750);
  }
  return null;
}
