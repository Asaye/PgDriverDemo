const PgDriver = require('./PgDriver');
const db = new PgDriver();
const config = {
   "host": "localhost", 
   "port": 5432,
   "user": "postgres",
   "password": "postgres",
   "database": "postgres"
};

db.connect(config, (err, res) => {
   if (err) {
       console.log("connection error.");
       return;
   }
   console.log(res); // connected
});

db.query("select * from customers", (err, res) => {
   if (err) {
      console.log("error occurred during query.");
      return;
   }
   console.log("Result set in JSON format is:");
   console.log(res);
   db.close();
});
