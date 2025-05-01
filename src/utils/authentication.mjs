import jwt from "jsonwebtoken";
import User from "../Database/Schema/userSchema.mjs";

export const isAuthenticated = async (request, response, next) => {
  const { token } = request.cookies;
  if (!token)
    return response.status(400).send({ msg: "Please authenticate first" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) throw new Error("Cannot fetch the user");
    request.user = user;
    next();
  } catch (error) {
    return response.status(400).send({ msg: error.message });
  }
};
