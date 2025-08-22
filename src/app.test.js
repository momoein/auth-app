const request = require("supertest");
const app = require("./app");
const db = require("./db");

// Before all tests, clear the user table to ensure a clean state
beforeAll((done) => {
  db.run("DELETE FROM users", done);
});

describe("Auth API", () => {
  let token;

  // Test Case 1: Successful Signup
  test("Should successfully sign up a new user", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ email: "test@example.com", password: "123password" });

    expect(res.statusCode).toBe(200);
    expect(res.headers['set-cookie']).toBeDefined();
  });

  // Test Case 2: Signup with existing email should fail
  test("Should return an error if email already exists during signup", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ email: "test@example.com", password: "newpassword" });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("User already exists");
  });

  // Test Case 3: Signup with missing email should fail
  test("Should return an error if email is missing during signup", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ password: "123password" });
    
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("Invalid input");
  });

  // Test Case 4: Successful Login
  test("Should successfully log in with correct credentials", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "test@example.com", password: "123password" });
      
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("Logged in successfully");
    expect(res.headers['set-cookie']).toBeDefined();
    token = res.headers['set-cookie'][0].split(';')[0].split('=')[1];
  });

  // Test Case 5: Login with wrong password should fail
  test("Should return an error for wrong password during login", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "test@example.com", password: "wrongpassword" });
      
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("Wrong password");
  });

  // Test Case 6: Login with non-existent user should fail
  test("Should return an error for a non-existent user during login", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "nonexistent@example.com", password: "123password" });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("User not found");
  });

  // Test Case 7: Accessing a protected route (profile) with a valid token
  test("Should allow access to profile with a valid token", async () => {
    const res = await request(app)
      .get("/profile")
      .set("Cookie", `token=${token}`);
      
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("Welcome test@example.com");
  });

  // Test Case 8: Accessing a protected route without a token
  test("Should deny access to profile without a token", async () => {
    const res = await request(app).get("/profile");
    
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("No token");
  });

  // Test Case 9: Accessing a protected route with an invalid token
  test("Should deny access to profile with an invalid token", async () => {
    const res = await request(app)
      .get("/profile")
      .set("Cookie", "token=invalid.token.here");

    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("Invalid token");
  });

  // Test Case 10: Successful Logout
  test("Should successfully log out and clear the cookie", async () => {
    const agent = request.agent(app);
    // Log in first to get a valid cookie
    await agent.post("/login").send({ email: "test@example.com", password: "123password" });
    
    // Now perform the logout
    const res = await agent.post("/logout");
      
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("Logged out");
    expect(res.headers['set-cookie']).toBeDefined();
    // Correctly check for a past expiration date, which indicates the cookie has been cleared
    expect(res.headers['set-cookie'][0]).toContain('Expires=');
    expect(res.headers['set-cookie'][0]).toContain('1970');
  });

  // Test Case 11: Accessing profile after logout should fail
  test("Should deny access to profile after logout", async () => {
    // To ensure a clean state, create a new agent
    const agent = request.agent(app);
    await agent.post("/login").send({ email: "test@example.com", password: "123password" });
    
    // Log out to clear the cookie
    await agent.post("/logout");

    // Now try to access the profile with the cleared cookie state
    const res = await agent.get("/profile");
      
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("No token");
  });
});
