import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

export const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error("MONGODB_URI is not defined in the environment variables");
  }

  mongoose
    .connect(uri)
    .then(() => {
      console.log("Database connected");
    })
    .catch((error) => {
      console.log(error);
      console.log("Error connecting to database");
    });
};
