import express from "express";
import cors from "cors";
import { analyzeUrl } from "./Scanner";

const app = express();
app.use(express.json());
app.use(cors());

app.post("/api/check", async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing 'url' in body" });
  }

  try {
    const result = await analyzeUrl(url);
    return res.json(result);
  } catch (err) {
    console.error("analyze error:", err);
    return res.status(500).json({ error: "Server error", detail: String(err) });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Phisherman backend listening on ${port}`));
