import { exchangeForCookie } from "@/lib/auth-route";

export const POST = (req: Request) => exchangeForCookie(req, "/v1/signup");
