const mongoose = require('mongoose');
const app = require('./app');
const dotenv = require('dotenv');
dotenv.config();
// require('dotenv').config()

main().catch(err => console.log(err));
async function main() {
  await mongoose.connect(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`);
  // await mongoose.connect('mongodb://127.0.0.1:27017/comp2537w1');

  // use `await mongoose.connect('mongodb://user:password@127.0.0.1:27017/test');` if your database has auth enabled
  console.log("connected to db");
  app.listen(process.env.PORT || 3000, () => {
    console.log('server is running on port 3000');
  });
}