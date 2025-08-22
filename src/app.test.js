const request = require("supertest");
const app = require("./app");
const db = require("./db");

beforeAll((done) => {
  db.run("DELETE FROM users", done); // پاک کردن دیتا قبل تست
});

describe("Auth API", () => {
  let token;

  test("Signup", async () => {
    const res = await request(app).post("/signup").send({
      email: "test@example.com",
      password: "123456",
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.email).toBe("test@example.com");
  });

  test("Login", async () => {
    const res = await request(app).post("/login").send({
      email: "test@example.com",
      password: "123456",
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.token).toBeDefined();
    token = res.body.token;
  });

  test("Access profile with token", async () => {
    const res = await request(app).get("/profile").set("Authorization", `Bearer ${token}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toContain("test@example.com");
  });
});
