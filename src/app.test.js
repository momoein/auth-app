const request = require("supertest");
const app = require("./app");
const db = require("./db");

beforeAll((done) => {
  db.run("DELETE FROM users", done);
});

describe("Auth API", () => {
  let token;

  // Test Case 1: Successful Signup with new fields
  test("Should successfully sign up a new user with all fields", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ 
        fullName: "Rasoul Khoshkalam",
        email: "rasoul.test@example.com",
        password: "testpassword123",
        gender: "male",
        dob: "1990-01-01"
      });

    expect(res.statusCode).toBe(200);
    expect(res.headers['set-cookie']).toBeDefined();
  });

  // Test Case 2: Signup with missing fields should fail
  test("Should return an error if a required field is missing during signup", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ 
        fullName: "Rasoul Khoshkalam",
        email: "incomplete@example.com",
        password: "testpassword123",
        gender: "male"
      });
    
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("All fields are required");
  });

    // Test Case 2.1: Signup with invalid email format should fail
  test("Should return an error if email format is invalid during signup", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ 
        fullName: "Rasoul Khoshkalam",
        email: "invalid-email-format", // not a valid email
        password: "testpassword123",
        gender: "male",
        dob: "1990-01-01"
      });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("Invalid email format");
  });

  // Test Case 3: Signup with existing email should fail
  test("Should return an error if email already exists during signup", async () => {
    const res = await request(app)
      .post("/signup")
      .send({ 
        fullName: "Rasoul Khoshkalam",
        email: "rasoul.test@example.com",
        password: "newpassword",
        gender: "male",
        dob: "1990-01-01"
      });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("User with this email already exists");
  });

  // Test Case 4: Successful Login
  test("Should successfully log in with correct credentials", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "rasoul.test@example.com", password: "testpassword123" });
      
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("Logged in successfully");
    expect(res.headers['set-cookie']).toBeDefined();
    token = res.headers['set-cookie'][0].split(';')[0].split('=')[1];
  });

  // Test Case 5: Login with wrong password should fail
  test("Should return an error for wrong password during login", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "rasoul.test@example.com", password: "wrongpassword" });
      
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("Wrong password");
  });

  // Test Case 6: Accessing a protected route (profile) with a valid token
  test("Should return user data when accessing profile with a valid token", async () => {
    const res = await request(app)
      .get("/profile")
      .set("Cookie", `token=${token}`);
      
    expect(res.statusCode).toBe(200);
    expect(res.body.fullName).toBe("Rasoul Khoshkalam");
    expect(res.body.email).toBe("rasoul.test@example.com");
    expect(res.body.gender).toBe("male");
    expect(res.body.dob).toBe("1990-01-01");
  });

  // Test Case 7: Accessing a protected route without a token
  test("Should deny access to profile without a token", async () => {
    const res = await request(app).get("/profile");
    
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe("No token");
  });

  // Test Case 8: Successful Logout
  test("Should successfully log out and clear the cookie", async () => {
    const agent = request.agent(app);
    // Log in first to get a valid cookie
    await agent.post("/login").send({ email: "rasoul.test@example.com", password: "testpassword123" });
    
    // Now perform the logout
    const res = await agent.post("/logout");
      
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe("Logged out");
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toContain('Expires=');
    expect(res.headers['set-cookie'][0]).toContain('1970');
  });
});