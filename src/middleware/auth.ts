import { Request, Response, NextFunction } from "express";
import { verifyApiKey } from "../utils/apiKeys";

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const authHeader = req.headers.authorization;
  const adminApiKey = process.env.ADMIN_API_KEY || "";

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next();
  }

  const token = authHeader.slice(7).trim();

  if (!token) {
    return next();
  }

  if (adminApiKey && token === adminApiKey) {
    req.isAdmin = true;

    const metadata = await verifyApiKey(token);
    if (metadata) {
      req.apiKey = metadata;
    }

    return next();
  }

  const metadata = await verifyApiKey(token);
  if (metadata) {
    req.apiKey = metadata;
  }

  next();
}
