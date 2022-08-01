import jwt from "jsonwebtoken";

export default (req, res, next) => {
  const token = (req.headers.authorization || "").replace(/Bearer\s?/, "");

  if (token) {
    try {
      const decoded = jwt.verify(token, "secret123");
      res.userId = decoded._id;

      next();
    } catch (e) {
      return res.status(403).json({
        message: "Ошибка ",
      });
    }
  } else {
    res.status(403).json({
      message: "Нет доступа",
    });
  }
};
