import { Request, Response } from "express";
import { backpressure, getInFlightCount } from "../src/middleware/backpressure";

describe("Concurrency Middleware", () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: jest.Mock;

    beforeEach(() => {
        mockReq = {};
        mockNext = jest.fn();
        mockRes = {
            on: jest.fn(),
            removeListener: jest.fn(),
            set: jest.fn(),
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        };
        // Reset inFlightRequests for testing (would ideally be exposed or we recreate the logic here to verify its limits but it's module scoped)
    });

    test("backpressure passes request when below limit", () => {
        backpressure(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalled();
        expect(getInFlightCount()).toBeGreaterThan(0);
        
        // Simulate response finish
        const onFinishCall = (mockRes.on as jest.Mock).mock.calls.find(c => c[0] === "finish");
        if (onFinishCall) {
            onFinishCall[1]();
        }
    });

});
