import { Request, Response, NextFunction } from "express";

const MAX_INFLIGHT_REQUESTS = Number(process.env.MAX_INFLIGHT_REQUESTS) || 200;
let inFlightRequests = 0;

export const backpressure = (req: Request, res: Response, next: NextFunction) => {
  if (inFlightRequests >= MAX_INFLIGHT_REQUESTS) {
    res.set("Retry-After", "5");
    return res.status(503).json({
      error: "Service Unavailable",
      detail: "Server is currently overloaded, please try again later.",
    });
  }

  inFlightRequests++;

  let cleanedUp = false;
  const onFinish = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    inFlightRequests = Math.max(0, inFlightRequests - 1);
    res.removeListener("finish", onFinish);
    res.removeListener("close", onFinish);
  };

  res.on("finish", onFinish);
  res.on("close", onFinish);

  next();
};

export const getInFlightCount = () => inFlightRequests;
