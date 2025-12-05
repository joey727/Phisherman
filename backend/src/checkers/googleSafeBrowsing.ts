import axios from "axios";
import dotenv from "dotenv";

dotenv.config();


export async function checkSafeBrowsing(url: string) {

  try {
    const api_key = process.env.GOOGLE_SAFE_API_KEY;

    if (!api_key) {
      console.error("safe browsing key missing");
      return { score: 0 }
    }

    const r = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${api_key}`,
      {
        client: { clientId: "phish-detector", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }
    );

    console.log("safe browsing response: ", r.data);

    if (r.data?.matches) {
      return {
        score: 50,
        reason: "Google Safe Browsing flagged this URL as dangerous",
      };
    }

    return { score: 0 };
  } catch (err: any) {
    console.error("safe browsing error: ", err.r?.data || err.message); 
    return { score: 0 }
  }
}
