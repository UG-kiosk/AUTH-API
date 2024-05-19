import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { MongoError } from "mongodb";
import { Request, Response } from "express";
import { User } from "../models/user.model";

dotenv.config();

export const register = async (req: Request, res: Response) => {
  let { username, email, password } = req.body;

  try {
    const salt = await bcrypt.genSalt(10);
    password = await bcrypt.hash(password, salt);

    const user = new User({
      username,
      email,
      password,
    });

    const savedUser = await user.save();
    res.send({ message: "User registered" });
  } catch (error) {
    if (error instanceof MongoError && error.code === 11000) {
      res.status(409).send({ message: "E-mail or username already exist" });
    } else {
      res.status(500).send({ message: "Something went wrong" });
    }
  }
};

export const login = async (req: Request, res: Response) => {
  let { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send({ message: "Invalid password" });
    }

    const jwt_secret = process.env.JWT_SECRET;
    if (!jwt_secret) {
      throw new Error("JWT secret is not defined in the environment variables");
    }
    const access_token_lifetime = process.env.ACCESS_TOKEN_LIFETIME;
    if (!access_token_lifetime) {
      throw new Error(
        "ACCESS_TOKEN_LIFETIME is not defined in the environment variables",
      );
    }
    const refresh_token_lifetime = process.env.REFRESH_TOKEN_LIFETIME;
    if (!refresh_token_lifetime) {
      throw new Error(
        "REFRESH_TOKEN_LIFETIME is not defined in the environment variables",
      );
    }

    const accessToken = jwt.sign({ username: user.username }, jwt_secret, {
      expiresIn: access_token_lifetime,
    });

    const refreshToken = jwt.sign({ username: user.username }, jwt_secret, {
      expiresIn: refresh_token_lifetime,
    });

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      // secure: true, // for https
      sameSite: "none",
      maxAge: 3600000, // 1 hour
    });

    res.status(200).send({ accessToken });
  } catch (error) {
    res.status(500).send({ message: "Something went wrong" });
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  const cookies = req.cookies;

  if (!cookies.jwt) {
    return res.status(401).send({ message: "Unauthorized" });
  }

  const jwt_secret = process.env.JWT_SECRET;
  if (!jwt_secret) {
    throw new Error("JWT secret is not defined in the environment variables");
  }

  jwt.verify(cookies.jwt, jwt_secret, async (error: any, decoded: any) => {
    try {
      if (error) {
        return res.status(404).send({ message: "Forbidden" });
      }

      const user = await User.findOne({ username: decoded.username });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      const access_token_lifetime: string | undefined =
        process.env.ACCESS_TOKEN_LIFETIME;
      if (!access_token_lifetime) {
        throw new Error(
          "ACCESS_TOKEN_LIFETIME is not defined in the environment variables",
        );
      }

      const accessToken: string = jwt.sign(
        { username: user.username },
        jwt_secret,
        {
          expiresIn: access_token_lifetime,
        },
      );

      res.status(200).send({ accessToken });
    } catch (error) {
      res.status(500).send({ message: "Something went wrong" });
    }
  });
};

export const logout = (req: Request, res: Response) => {
  const cookies = req.cookies;
  if (!cookies.jwt) {
    return res.status(204).send({ message: "No token provided" });
  }
  res.clearCookie("jwt", {
    httpOnly: true,
    // secure: true, // for https
    sameSite: "none",
  });

  res.status(200).send({ message: "Logged out" });
};

export const validateRequest = (req: Request, res: Response) => {
  res.status(200).send({ message: "Valid request" });
};

interface RequestWithUsername extends Request {
  username?: string;
}

export const changePassword = async (
  req: RequestWithUsername,
  res: Response,
) => {
  const { oldPassword, newPassword } = req.body;
  try {
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .send({ message: "Please provide old and new password" });
    }

    if (!req.username) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    const user = await User.findOne({ username: req.username });
    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    const validPassword = await bcrypt.compare(oldPassword, user.password);
    if (!validPassword) {
      return res.status(401).send({ message: "Wrong password" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    await user.save();

    res.status(200).send({ message: "Password changed" });
  } catch (error) {
    res.status(500).send({ message: "Something went wrong..." });
  }
};
