import axios from "axios";
import dotenv from "dotenv";

dotenv.config();


export async function checkSafeBrowsing(url: string) {
  if (!process.env.GOOGLE_SAFE_API_KEY) return { score: 0 };

  try {
    const r = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_API_KEY}`,
      {
        client: { clientId: "phish-detector", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "PHISHING", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }
    );

    if (r.data && r.data.matches) {
      return {
        score: 100,
        reason: "Google Safe Browsing flagged this URL as dangerous",
      };
    }

    return { score: 0 };
  } catch (err) {
    console.error("safe browsing error: ", err); 
    return { score: 0 }
  }
}
