// const url = require('url');
const express = require('express');
const app = express();
const session = require('express-session');
const ObjectId = require('mongodb').ObjectId;
const usersModel = require('./models/w1users');
const bcrypt = require('bcrypt');
const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * milliseconds)
const saltRounds = 12;
// 1 - import 
let ejs = require('ejs');
// 2 - set the view engine to ejs
app.set('view engine', 'ejs')

const navLinks = [
  {name: "Home", link: "/"},
  {name: "Members", link: "/members"},
  {name: "Admin", link: "/admin"},
  {name: "Login", link: "/login"},
  {name: "Sign Up", link: "/signUp"}
]

var MongoDBStore = require('connect-mongodb-session')(session);


const dotenv = require('dotenv');
dotenv.config();

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

// var { database } = include("databaseConnection");
// const userCollection = database.db(mongodb_database).collection("w1users");

var dbStore = new MongoDBStore({
  // uri: 'mongodb://localhost:27017/connect_mongodb_session_test',
  uri: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`,
  collection: 'mySessions'
});


// replace the in-memory array session store with a database session store
app.use(session({
  secret: node_session_secret,
  store: dbStore,
  resave: false,
  saveUninitialized: false,
}));

// public routes
app.get('/', (req, res) => {
  if (!req.session.GLOBAL_AUTHENTICATED) {
    return res.render('index.ejs',
    {navLinks: navLinks});
  } else {
    return res.render('indexLoggedIn.ejs',
    {navLinks: navLinks});
  }
});


app.get('/login', (req, res) => {
  return res.render('login.ejs', {navLinks: navLinks});
});

app.get("/signUp", (req, res) => {
  return res.render('signUp.ejs', {navLinks: navLinks});
});

// GLOBAL_AUTHENTICATED = false;
app.use(express.urlencoded({ extended: false }))
// built-in middleware function in Express. It parses incoming requests with urlencoded payloads and is based on body-parser.
const Joi = require('joi');
app.use(express.json()) // built-in middleware function in Express. It parses incoming requests with JSON payloads and is based on body-parser.
app.post('/login', async (req, res) => {
  // set a global variable to true if the user is authenticated

  // sanitize the input using Joi

  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  try {
    const result = await usersModel.findOne({
      email: req.body.email
    })

    if (bcrypt.compareSync(req.body.password, result?.password)) {
      req.session.GLOBAL_AUTHENTICATED = true;
      req.session.loggedType = result?.type;
      req.session.loggedUsername = result?.username;
      req.session.loggedPassword = req.body.password;
      req.session.cookie.expires = new Date(Date.now() + expireTime);
      res.redirect('/members');
    } else {
      res.render('wrongPassword.ejs', {navLinks: navLinks})
      
    }

  } catch (error) {
    console.log(error);
  }

});

app.post("/signUp", async (req, res) => {
  console.log("Submitting user");
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(`Please enter valid information
    <a href="/signUp">Try Again</a>`);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  console.log("Inserting user");
  await usersModel.collection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
    type: "user"
  });
  console.log("Inserted user");

  try {
    const result = await usersModel.findOne({
      email: req.body.email
    })
      req.session.GLOBAL_AUTHENTICATED = true;
      req.session.loggedType = result?.type;
      req.session.loggedUsername = result?.username;
      req.session.loggedPassword = req.body.password;
      req.session.cookie.expires = new Date(Date.now() + expireTime);
      res.redirect('/members');
  } catch (error) {
    console.log(error);
  }
});

// only for authenticated users
const authenticatedOnly = (req, res, next) => {
  if (!req.session.GLOBAL_AUTHENTICATED) {
    return res.redirect('/login');
  }
  next(); // allow the next route to run
};
app.use(authenticatedOnly);

app.use(express.static('public')) // built-in middleware function in Express. It serves static files and is based on serve-static.

app.get('/members', async (req, res) => {
  // serve one of the three images randomly
  // generate a random number between 1 and 3
  const randomImageNumber = Math.floor(Math.random() * 7) + 1;
  const imageName1 = `00${randomImageNumber}.png`;
  const imageName2 = `00${randomImageNumber + 1}.png`;
  const imageName3 = `00${randomImageNumber + 2}.png`;
  // HTMLResponse = `
  //   <h1> Hello ${req.session.loggedUsername} </h1>
  //   <br>
  //   <img src="${imageName}" />
  //   <br>
  //   <a href="/logout">Logout</a>
  //   `
  // res.send(HTMLResponse);

  const result = await usersModel.findOne({ username: req.session.loggedUsername });
  return res.render('protectedRoute.ejs', {
    "x": req.session.loggedUsername,
    "y": imageName1,
    "z": imageName2,
    "w": imageName3,
    "isAdmin": req.session.loggedType == 'admin',
    "todos":result?.todos, 
    "navLinks": navLinks
  }
  )
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  // var html = `
  //   You are logged out.
  //   <a href='/'>Home</a>
  //   `;
  // res.send(html);
  return res.redirect('/');
});

app.post('/addNewTodoItem', async (req, res) => {
  const result = await usersModel.updateOne(
    { username: req.session.loggedUsername },
    { $push: { todos: {
      "name": req.body.newItemLabel
    } 
  } 
}
  )
  return res.redirect('/members');
});

app.post('/deleteTodoItem', async (req, res) => {
  const result = await usersModel.updateOne(
    { username: req.session.loggedUsername });
  
  const newArr = result.todos = result.todos.filter((item) => {
      return item.name != req.body.x;
    });

  const updatedResult = await usersModel.updateOne(
    { username: req.session.loggedUsername },
    { $set: { todos: newArr } }
  )

  res.redirect('/members');
});

app.post('/updateTodoItem', async (req, res) => {
  const result = await usersModel.findOne({ username: req.session.loggedUsername });

  const newArr = result.todos.map((todoItem) => {
    if (todoItem.name == req.body.x) {
      todoItem.done = !todoItem.done;
    }
    return todoItem;
  });

  const updatedResult = await usersModel.updateOne(
    { username: req.session.loggedUsername },
    { $set: { todos: newArr } }
  );
  res.redirect('/members');
});

// only for admins
const protectedRouteForAdminsOnlyMiddlewareFunction = async (req, res, next) => {
  try {
    const result = await usersModel.findOne({ username: req.session.loggedUsername }
    )
    if (result?.type != 'admin') {
      return res.status(403).render('notAdmin.ejs', {navLinks: navLinks});
    }
    next(); // allow the next route to run
  } catch (error) {
    console.log(error);
  }
};
app.use(protectedRouteForAdminsOnlyMiddlewareFunction);

app.get('/admin', async (req, res) => {
  const result = await usersModel.find({});
  return res.render('admin.ejs', {navLinks: navLinks, users: result});
});

app.post('/promoteAdmin', async (req, res) => {
  const userID = req.body.userId;
  console.log(userID);
await usersModel.updateOne(
  { _id: new ObjectId(userID) },
  { $set: { type: "admin" } }
);
console.log("Promoted user");
res.redirect('/admin');
});

app.post('/demoteUser', async (req, res) => {
  const userID = req.body.userId;
  console.log(userID);
await usersModel.updateOne(
  { _id: new ObjectId(userID) },
  { $set: { type: "user" } }
);
console.log("Demoted user");
res.redirect('/admin');
});

app.get('*', (req, res) => {
  return res.status(404).render('404.ejs', {navLinks: navLinks});
});




module.exports = app;