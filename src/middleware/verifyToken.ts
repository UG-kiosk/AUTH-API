import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { Request as ExpressRequest, Response, NextFunction } from "express";

dotenv.config();

interface Request extends ExpressRequest {
  username?: string;
}

export const verifyToken = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (
    !authHeader ||
    (!Array.isArray(authHeader) && !authHeader.startsWith("Bearer "))
  ) {
    return res.status(403).send({ message: "No token provided" });
  }

  const token = Array.isArray(authHeader)
    ? authHeader[0].split(" ")[1]
    : authHeader.split(" ")[1];

  const jwt_secret = process.env.JWT_SECRET;
  if (!jwt_secret) {
    throw new Error("JWT_SECRET is not defined in the environment variables");
  }

  const refresh_token_lifetime = process.env.REFRESH_TOKEN_LIFETIME;
  if (!refresh_token_lifetime) {
    throw new Error(
      "REFRESH_TOKEN_LIFETIME is not defined in the environment variables",
    );
  }

  jwt.verify(token, jwt_secret, (error: any, decoded: any) => {
    if (error) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.username = decoded.username;

    const rotateRefreshToken = jwt.sign(
      { username: req.username },
      jwt_secret,
      {
        expiresIn: refresh_token_lifetime,
      },
    );

    res.clearCookie("jwt", {
      httpOnly: true,
      // secure: true, // for https
      sameSite: "none",
    });
    res.cookie("jwt", rotateRefreshToken, {
      httpOnly: true,
      // secure: true, // for https
      sameSite: "none",
    });

    next();
  });
};
